//! Independent single-transaction feed execution. Never commits to canonical state.
use alloy_consensus::{Header, Transaction, transaction::Recovered};
use alloy_eips::eip2718::Typed2718;
use alloy_evm::block::BlockExecutor as _;
use alloy_primitives::{B256, U256};
use arb_reth_evm::{ArbEvmConfig, ArbNextBlockEnvAttributes};
use arb_revm::{
    ArbosState,
    executor::{ArbExecCfg, ArbParentHeader, digest_message},
};
use arbitrum_alloy_consensus::ArbTxEnvelope;
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use crossbeam_channel::{Receiver, Sender};
use eyre::{Result, eyre};
use jsonrpsee::{RpcModule, SubscriptionMessage, types::ErrorObjectOwned};
use reth_evm::{ConfigureEvm as _, Evm as _, execute::BlockBuilder as _};
use reth_primitives_traits::SealedHeader;
use reth_provider::{BlockNumReader, HeaderProvider, StateProviderFactory};
use reth_revm::{State, database::StateProviderDatabase};
use revm::{Database as _, context_interface::ContextTr as _};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

/// Opt-in, bounded speculative lane. Slow consumers never block canonical import.
#[derive(Clone)]
pub struct SpecReceipts {
    events: broadcast::Sender<Arc<Value>>,
    ingress: Sender<(BroadcastFeedMessage, Instant)>,
    receiver: Receiver<(BroadcastFeedMessage, Instant)>,
    workers: usize,
}

struct BlockJob {
    parent: SealedHeader<Header>,
    attrs: ArbNextBlockEnvAttributes,
    sequence: u64,
    arrival: Instant,
}
struct Job {
    block: Arc<BlockJob>,
    tx: ArbTxEnvelope,
    index: u64,
    queued: Instant,
}

impl SpecReceipts {
    pub(crate) fn new(workers: usize) -> Result<Self> {
        eyre::ensure!(
            (1..=32).contains(&workers),
            "spec receipt workers must be 1..=32"
        );
        let (ingress, receiver) = crossbeam_channel::bounded(256);
        let (events, _) = broadcast::channel(8192);
        Ok(Self {
            events,
            ingress,
            receiver,
            workers,
        })
    }

    pub(crate) fn submit(&self, message: &BroadcastFeedMessage, arrival: Instant) {
        if self.events.receiver_count() == 0 {
            return;
        }
        if self.ingress.try_send((message.clone(), arrival)).is_err() {
            metrics::counter!("arb_reth.spec.ingress_dropped").increment(1);
        }
    }

    pub(crate) fn start<P>(
        &self,
        provider: P,
        evm: ArbEvmConfig,
        chain_id: u64,
        genesis: u64,
    ) -> Result<()>
    where
        P: StateProviderFactory
            + HeaderProvider<Header = Header>
            + BlockNumReader
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let (jobs, receiver) = crossbeam_channel::bounded::<Job>(8192);
        for id in 0..self.workers {
            let receiver = receiver.clone();
            let provider = provider.clone();
            let evm = evm.clone();
            let events = self.events.clone();
            std::thread::Builder::new().name(format!("arb-spec-{id}")).spawn(move || {
                while let Ok(job) = receiver.recv() {
                    if events.receiver_count() == 0 { continue; }
                    match execute(&provider, &evm, &job) {
                        Ok(Some(event)) => { let _ = events.send(Arc::new(event)); }
                        Ok(None) => {}
                        Err(error) => {
                            metrics::counter!("arb_reth.spec.execution_errors").increment(1);
                            tracing::debug!(target: "arb-reth::spec", %error, tx = %job.tx.hash(), "spec execution skipped");
                        }
                    }
                }
            })?;
        }
        let ingress = self.receiver.clone();
        let events = self.events.clone();
        std::thread::Builder::new()
            .name("arb-spec-dispatch".into())
            .spawn(move || {
                let mut seen = HashSet::new();
                let mut order = VecDeque::new();
                while let Ok((message, arrival)) = ingress.recv() {
                    if events.receiver_count() == 0 {
                        continue;
                    }
                    let prepared = (|| -> Result<_> {
                        let parent = provider
                            .sealed_header(provider.best_block_number()?)?
                            .ok_or_else(|| eyre!("missing spec parent"))?;
                        if message.sequence_number.checked_add(genesis)
                            != parent.number.checked_add(1)
                        {
                            metrics::counter!("arb_reth.spec.not_next_message").increment(1);
                            return Ok(None);
                        }
                        // Match Nitro's L2-message-only hot lane, not delayed inbox execution.
                        if message
                            .message_with_meta_data
                            .l1_incoming_message
                            .header
                            .kind
                            != 3
                        {
                            return Ok(None);
                        }
                        let version =
                            arbitrum_alloy_consensus::header::ArbHeaderInfo::decode_header(
                                parent.header(),
                            )?
                            .arbos_format_version;
                        let input = digest_message(
                            &message,
                            ArbParentHeader {
                                number: parent.number,
                                timestamp: parent.timestamp,
                                beneficiary: parent.beneficiary,
                                basefee: parent.base_fee_per_gas.unwrap_or(0),
                                gas_limit: parent.gas_limit,
                                difficulty: parent.difficulty,
                                prevrandao: Some(parent.mix_hash),
                            },
                            ArbExecCfg {
                                chain_id,
                                ..Default::default()
                            },
                            version as u8,
                        )?;
                        let attrs = ArbNextBlockEnvAttributes {
                            timestamp: input.message.l1_timestamp.max(parent.timestamp),
                            suggested_fee_recipient: input.message.poster,
                            prev_randao: B256::ZERO,
                            gas_limit: input.cfg.block_gas_limit,
                            l1_block_number: input.message.l1_block_number,
                            l1_base_fee_wei: input.message.l1_base_fee_wei,
                            arbos_format_version: version,
                            delayed_messages_read: input.message.delayed_messages_read,
                            extra_data: Default::default(),
                            withdrawals: None,
                            finish_timing_out: Default::default(),
                        };
                        Ok(Some((
                            Arc::new(BlockJob {
                                parent,
                                attrs,
                                sequence: message.sequence_number,
                                arrival,
                            }),
                            input.message.txs,
                        )))
                    })();
                    match prepared {
                        Ok(Some((block, txs))) => {
                            for (index, tx) in txs.into_iter().enumerate() {
                                let hash = tx.hash();
                                if seen.contains(&hash) {
                                    continue;
                                }
                                if jobs
                                    .try_send(Job {
                                        block: block.clone(),
                                        tx,
                                        index: index as u64 + 1,
                                        queued: Instant::now(),
                                    })
                                    .is_ok()
                                {
                                    seen.insert(hash);
                                    order.push_back(hash);
                                    if order.len() > 8192 {
                                        seen.remove(&order.pop_front().unwrap());
                                    }
                                } else {
                                    metrics::counter!("arb_reth.spec.jobs_dropped").increment(1);
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::debug!(target: "arb-reth::spec", %error, "spec feed skipped");
                        }
                    }
                }
            })?;
        Ok(())
    }

    pub(crate) fn module(&self) -> Result<RpcModule<()>> {
        let mut module = RpcModule::new(self.events.clone());
        module.register_subscription("arbtx_subscribe", "arbtx_subscription", "arbtx_unsubscribe",
            |params, pending, events, _| async move {
                if params.one::<String>().ok().as_deref() != Some("speculativeReceipts") {
                    pending.reject(ErrorObjectOwned::owned(-32602, "expected speculativeReceipts", None::<()>)).await;
                    return Ok(());
                }
                let mut receiver = events.subscribe();
                let sink = pending.accept().await?;
                loop {
                    let event = tokio::select! {
                        _ = sink.closed() => break,
                        event = receiver.recv() => match event { Ok(event) => event, Err(_) => break },
                    };
                    let msg = SubscriptionMessage::new("arbtx_subscription", sink.subscription_id(), event.as_ref())?;
                    // Do not retain stale speculative results for an unresponsive client.
                    if !matches!(tokio::time::timeout(std::time::Duration::from_secs(1), sink.send(msg)).await, Ok(Ok(()))) { break; }
                }
                Ok(())
            })?;
        Ok(module.remove_context())
    }
}

fn execute<P>(provider: &P, evm: &ArbEvmConfig, job: &Job) -> Result<Option<Value>>
where
    P: StateProviderFactory + HeaderProvider<Header = Header> + BlockNumReader,
{
    let started = Instant::now();
    let b = &job.block;
    if provider
        .sealed_header(provider.best_block_number()?)?
        .is_none_or(|h| h.hash() != b.parent.hash())
    {
        metrics::counter!("arb_reth.spec.stale_jobs").increment(1);
        return Ok(None);
    }
    let db = provider.state_by_block_hash(b.parent.hash())?;
    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(db))
        .build();
    let mut builder = evm.builder_for_next_block(&mut state, &b.parent, b.attrs.clone())?;
    builder.apply_pre_execution_changes()?;
    let fee = ArbosState::open()
        .l2_pricing
        .base_fee_wei
        .get(builder.evm_mut().ctx_mut().journal_mut())
        .map_err(|e| eyre!("spec base fee: {e}"))?;
    let fee = u64::try_from(fee).unwrap_or(u64::MAX);
    builder.evm_mut().ctx_mut().modify_block(|env| {
        env.inner.basefee = fee;
        env.base_fee_in_block = fee;
    });
    builder.evm_mut().ctx_mut().chain.base_fee_in_block = Some(fee);
    let mut prelude_gas = 0;
    if let Some(tx) = builder.executor().start_block_tx() {
        let sender = tx.sender()?;
        builder.execute_transaction_with_result_closure(
            Recovered::new_unchecked(tx, sender),
            |res| {
                prelude_gas = res.result.result.tx_gas_used();
            },
        )?;
    }
    let sender = job.tx.sender()?;
    let tx_started = Instant::now();
    let recovered = Recovered::new_unchecked(job.tx.clone(), sender);
    let output = builder
        .executor_mut()
        .execute_transaction_without_commit(&recovered)?;
    let execution_us = tx_started.elapsed().as_micros() as u64;
    let result = &output.result.result;
    if !result.is_success() {
        metrics::counter!("arb_reth.spec.reverted").increment(1);
        return Ok(None);
    }
    let mut deltas = Vec::new();
    for (address, account) in &output.result.state {
        if !account.is_touched() {
            continue;
        }
        let before = builder
            .evm_mut()
            .db_mut()
            .basic(*address)?
            .map(|a| a.balance)
            .unwrap_or_default();
        let after = if account.is_selfdestructed() {
            U256::ZERO
        } else {
            account.info.balance
        };
        if after > before {
            deltas.push((*address, after - before));
        }
    }
    deltas.sort_unstable_by_key(|(address, _)| *address);
    let hash = job.tx.hash();
    let number = b.parent.number + 1;
    let logs: Vec<_> = result
        .logs()
        .iter()
        .enumerate()
        .map(|(index, log)| {
            json!({
                "address":log.address, "topics":log.data.topics(), "data":log.data.data,
                "blockHash": B256::ZERO, "blockNumber": format!("0x{number:x}"),
                "transactionHash":hash, "transactionIndex":format!("0x{:x}",job.index),
                "logIndex":format!("0x{index:x}"), "removed":false,
            })
        })
        .collect();
    let gas = result.tx_gas_used();
    let elapsed = b.arrival.elapsed().as_micros() as u64;
    metrics::histogram!("arb_reth.spec.feed_to_result_seconds")
        .record(b.arrival.elapsed().as_secs_f64());
    metrics::counter!("arb_reth.spec.published").increment(1);
    Ok(Some(json!({
        "receipt": {
            "transactionHash":hash, "transactionIndex":format!("0x{:x}",job.index),
            "blockHash": B256::ZERO, "blockNumber":format!("0x{number:x}"),
            "from":sender, "to":job.tx.to(), "type":format!("0x{:x}",job.tx.ty()),
            "status":"0x1", "gasUsed":format!("0x{gas:x}"),
            "cumulativeGasUsed":format!("0x{:x}",gas+prelude_gas),
            "gasUsedForL1":format!("0x{:x}",output.gas_used_for_l1),
            "effectiveGasPrice":format!("0x{:x}",job.tx.effective_gas_price(Some(fee))),
            "contractAddress":result.created_address(),
            "logsBloom":alloy_primitives::logs_bloom(result.logs().iter()), "logs":logs,
        },
        "nativeBalanceDeltas":deltas.into_iter().map(|(address,amount)|json!({"address":address,"amount":format!("0x{amount:x}")})).collect::<Vec<_>>(),
        "speculation": {
            "baseBlockHash":b.parent.hash(), "baseStateRoot":b.parent.state_root,
            "baseBlockNumber":b.parent.number, "sequenceNumber":b.sequence,
            "queueUs":started.duration_since(job.queued).as_micros() as u64,
            "executionUs":execution_us, "workerUs":started.elapsed().as_micros() as u64,
            "feedToResultUs":elapsed,
            "readyUnixUs":SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64,
        }
    })))
}
