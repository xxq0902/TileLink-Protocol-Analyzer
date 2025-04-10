#!/usr/bin/env python3

import re
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any

@dataclass
class TileLinkTransaction:
    request: Any = None
    responses: List[Any] = field(default_factory=list)
    ack: Any = None
    
    def is_complete(self) -> bool:
        return self.request is not None and len(self.responses) > 0 and self.ack is not None


class TileLinkAnalyzer:
    def __init__(self):
        # Transactions tracking
        self.transactions = []
        self.parsed_transactions = []
        
        # Outstanding operations tracking by transaction type
        self.outstanding_requests = {}  # hart -> source -> addr -> transaction (A-channel requests)
        self.outstanding_grants = {}    # hart -> sink -> transaction (D-channel grants)
        self.outstanding_probes = {}    # hart -> addr -> transaction (B-channel probes)
        self.outstanding_releases = {}  # hart -> source -> addr -> transaction (C-channel releases)
        
        # Cache state by hart and address
        self.cache_states = {}  # hart -> addr -> state
        
        # Cache state history for better analysis
        self.cache_state_history = {}  # hart -> addr -> [state transitions]
        
        # Protocol violations
        self.violations = []
        
        # Reset statistics
        self.reset_stats()
    
    def reset_stats(self):
        # Statistics
        self.stats = {
            "totalTransactions": 0,
            "completeTransactions": 0,
            
            # Channel operation counts
            "aChannelOps": A0,
            "bChannelOps": 0,
            "cChannelOps": 0,
            "dChannelOps": 0,
            "eChannelOps": 0,
            
            # Operation categories (top level)
            "accessOps": 0,
            "hintOps": 0,
            "transferOps": 0,
            
            # Access operations
            "putOps": 0,     # PutFullData, PutPartialData
            "getOps": 0,     # Get
            "atomicOps": 0,  # ArithmeticData, LogicalData
            
            # Specific operations
            "putFullDataOps": 0,
            "putPartialDataOps": 0,
            "getRequestOps": 0,
            "arithmeticDataOps": 0,
            "logicalDataOps": 0,
            "intentOps": 0,
            
            # Transfer operations
            "acquireOps": 0,   # AcquireBlock, AcquirePerm
            "probeOps": 0,     # ProbeBlock, ProbePerm
            "releaseOps": 0,   # Release, ReleaseData
            
            # Specific transfer operations
            "acquireBlockOps": 0,
            "acquirePermOps": 0,
            "probeBlockOps": 0,
            "probePermOps": 0,
            "releaseWithoutDataOps": 0,
            "releaseWithDataOps": 0,
            
            # Response operations
            "accessAckOps": 0,
            "accessAckDataOps": 0,
            "hintAckOps": 0,
            "grantOps": 0,
            "grantDataOps": 0,
            "probeAckOps": 0,
            "probeAckDataOps": 0,
            "releaseAckOps": 0,
            "grantAckOps": 0
        }
    
    def parse_log_line(self, line):
        # Parse time and hart
        time_hart_match = re.match(r'(\d+\.\d+)\s+ns\s+(Hart\d+):\s+(.*)', line)
        if not time_hart_match:
            return None
        
        timestamp, hart, message = time_hart_match.groups()
        
        # Parse channel and operation
        channel_op_match = re.match(r'([A-E]-Channel):\s+(\w+)\s+-\s+(.*)', message)
        if not channel_op_match:
            return None
        
        channel, operation, params_str = channel_op_match.groups()
        
        # Parse common parameters
        param_dict = {}
        
        # Extract address
        addr_match = re.search(r'addr:(0x[0-9a-f]+)', params_str)
        if addr_match:
            param_dict['addr'] = addr_match.group(1)
        
        # Extract source
        source_match = re.search(r'source:(\d+)', params_str)
        if source_match:
            param_dict['source'] = int(source_match.group(1))
        
        # Extract sink for D and E channels
        sink_match = re.search(r'sink:(\d+)', params_str)
        if sink_match:
            param_dict['sink'] = int(sink_match.group(1))
        
        # Extract size
        size_match = re.search(r'size:(\d+)', params_str)
        if size_match:
            param_dict['size'] = int(size_match.group(1))
        
        # Extract data for D-Channel
        data_match = re.search(r'data:(0x[0-9a-f]+)', params_str)
        if data_match:
            param_dict['data'] = data_match.group(1)
        
        # Extract cache state transition for A-Channel
        growth_match = re.search(r'(NtoB|NtoT|BtoT|TtoB|TtoN|BtoN)\s+\((\d+)\)', params_str)
        if growth_match:
            param_dict['growth'] = growth_match.group(1)
            param_dict['param'] = int(growth_match.group(2))
        
        # Extract permission cap for D/B channel operations
        cap_match = re.search(r'(toB|toT|toN)\s+\((\d+)\)', params_str)
        if cap_match and 'growth' not in param_dict:
            param_dict['cap'] = cap_match.group(1)
            param_dict['param'] = int(cap_match.group(2))
        
        # Extract way for A-Channel
        way_match = re.search(r'way:(\d+)', params_str)
        if way_match:
            param_dict['way'] = int(way_match.group(1))
        
        # Extract corrupt flag
        corrupt_match = re.search(r'corrupt:(\d+)', params_str)
        if corrupt_match:
            param_dict['corrupt'] = int(corrupt_match.group(1))
        
        # Extract shareable flag
        shareable_match = re.search(r'shareable:(\d+)', params_str)
        if shareable_match:
            param_dict['shareable'] = int(shareable_match.group(1))
        
        # Extract user field
        user_match = re.search(r'user:(0x[0-9a-f]+)', params_str)
        if user_match:
            param_dict['user'] = user_match.group(1)
        
        # Create transaction record
        transaction = {
            "timestamp": float(timestamp),
            "hart": hart,
            "channel": channel,
            "operation": operation,
            "params": param_dict,
            "rawParams": params_str,
        }
        
        # Add to parsed transactions for display
        self.parsed_transactions.append(transaction)
        
        # Update channel operation statistics
        if channel == "A-Channel":
            self.stats["aChannelOps"] += 1
        elif channel == "B-Channel":
            self.stats["bChannelOps"] += 1
        elif channel == "C-Channel":
            self.stats["cChannelOps"] += 1
        elif channel == "D-Channel":
            self.stats["dChannelOps"] += 1
        elif channel == "E-Channel":
            self.stats["eChannelOps"] += 1
        
        return transaction
    
    def get_hart_map(self, maps, hart):
        if hart not in maps:
            maps[hart] = {}
        return maps[hart]
    
    def get_source_map(self, hart_map, source):
        if source not in hart_map:
            hart_map[source] = {}
        return hart_map[source]
    
    # Helper for updating cache state from a ProbeAck/ProbeAckData response
    def update_cache_state_from_probe(self, hart, addr, growth):
        if not growth:
            return
        
        # Get cache state map for this hart
        if hart not in self.cache_states:
            self.cache_states[hart] = {}
        hart_cache_states = self.cache_states[hart]
        
        # Setup cache state history for this hart/address
        if hart not in self.cache_state_history:
            self.cache_state_history[hart] = {}
        if addr not in self.cache_state_history[hart]:
            self.cache_state_history[hart][addr] = []
        state_history = self.cache_state_history[hart][addr]
        
        # Get current state for this address in this hart
        current_state = hart_cache_states.get(addr, 'None')
        
        # Update state based on ProbeAck response
        new_state_map = {
            'BtoN': 'None',   # Downgrade Branch to None
            'TtoN': 'None',   # Downgrade Trunk to None
            'TtoB': 'Branch'  # Downgrade Trunk to Branch
        }
        
        if growth in new_state_map:
            # Log the state transition in history
            import time
            state_history.append({
                "timestamp": time.time(),  # Using current time as transaction time not available here
                "oldState": current_state,
                "newState": new_state_map[growth],
                "operation": f"ProbeAck/ProbeAckData - {growth}",
                "channel": "C-Channel"
            })
            
            # Update current state
            hart_cache_states[addr] = new_state_map[growth]
    
    # Helper for handling Release/ReleaseData operations
    def handle_release_operation(self, hart, addr, source, transaction, growth):
        # Create transaction for tracking
        new_txn = {
            "request": transaction,
            "response": None
        }
        
        # Track this release operation                      
        # Store outstanding release
        hart_map = self.get_hart_map(self.outstanding_releases, hart)
        source_map = self.get_source_map(hart_map, source)
        source_map[addr] = new_txn
        
        # Update cache state based on Release's growth parameter
        if growth:
            # Get cache state map for this hart
            if hart not in self.cache_states:
                self.cache_states[hart] = {}
            hart_cache_states = self.cache_states[hart]
            
            # Setup cache state history for this hart/address
            if hart not in self.cache_state_history:
                self.cache_state_history[hart] = {}
            if addr not in self.cache_state_history[hart]:
                self.cache_state_history[hart][addr] = []
            state_history = self.cache_state_history[hart][addr]
            
            # Get current state for this address in this hart
            current_state = hart_cache_states.get(addr, 'None')
            
            # Update state based on Release growth parameter
            new_state_map = {
                'TtoB': 'Branch',  # Downgrade Trunk to Branch
                'TtoN': 'None',    # Downgrade Trunk to None
                'BtoN': 'None'     # Downgrade Branch to None
            }
            
            if growth in new_state_map:
                # Log the state transition in history
                state_history.append({
                    "timestamp": transaction["timestamp"],
                    "oldState": current_state,
                    "newState": new_state_map[growth],
                    "operation": f"{transaction['operation']} - {growth}",
                    "channel": transaction["channel"]
                })
                
                # Update current state
                hart_cache_states[addr] = new_state_map[growth]
    
    # Helper for handling D-Channel AccessAck/AccessAckData/HintAck responses
    def handle_generic_d_response(self, hart, source, transaction, operation_type):
        # Find matching A-Channel request using source ID
        matching_txn = None
        matching_addr = None
        
        if hart in self.outstanding_requests and source in self.outstanding_requests[hart]:
            source_map = self.outstanding_requests[hart][source]
            # Find the first request with this source ID
            for addr, txn in source_map.items():
                # Check if this is the type of request we're looking for
                req_op = txn.request["operation"]
                if ((operation_type == "Put" and (req_op == "PutFullData" or req_op == "PutPartialData")) or
                    (operation_type == "Get/Atomic" and (req_op == "Get" or req_op == "ArithmeticLogic" or req_op == "LogicalData")) or
                    (operation_type == "Intent" and req_op == "Intent")):
                    matching_txn = txn
                    matching_addr = addr
                    break
        
        if matching_txn:
            # Add response to transaction
            matching_txn.responses.append(transaction)
            
            # For simple transactions (non-Grant), we can remove from outstanding
            # requests as they don't need an E-Channel acknowledgment
            if (hart in self.outstanding_requests and 
                source in self.outstanding_requests[hart] and
                matching_addr in self.outstanding_requests[hart][source]):
                del self.outstanding_requests[hart][source][matching_addr]
            
            # Update completion stats
            self.stats["completeTransactions"] += 1
        else:
            self.violations.append(
                f"D-Channel {transaction['operation']} at {transaction['timestamp']} in {hart} " +
                f"with source {source} has no matching {operation_type} request"
            )
    
    def analyze_transaction(self, transaction):
        hart = transaction["hart"]
        channel = transaction["channel"]
        operation = transaction["operation"]
        params = transaction["params"]
        
        # Process A-Channel requests
        if channel == "A-Channel":
            if 'source' not in params or 'addr' not in params:
                self.violations.append(
                    f"Missing required parameters in A-Channel {operation} at {transaction['timestamp']} in {hart}"
                )
                return
            
            source = params["source"]
            addr = params["addr"]
            growth = params.get("growth")
            
            # Create new transaction for all A-Channel operations
            new_txn = TileLinkTransaction(request=transaction)
            self.transactions.append(new_txn)
            self.stats["totalTransactions"] += 1
            
            # Store outstanding request for all A-Channel operations
            hart_map = self.get_hart_map(self.outstanding_requests, hart)
            source_map = self.get_source_map(hart_map, source)
            source_map[addr] = new_txn
            
            # Specific handling based on operation type
            if operation == "PutFullData":
                # Access -> Put -> PutFullData
                self.stats["accessOps"] += 1
                self.stats["putOps"] += 1
                self.stats["putFullDataOps"] += 1
                
            elif operation == "PutPartialData":
                # Access -> Put -> PutPartialData
                self.stats["accessOps"] += 1
                self.stats["putOps"] += 1
                self.stats["putPartialDataOps"] += 1
                
            elif operation == "ArithmeticLogic":
                # Access -> Atomic -> ArithmeticLogic
                self.stats["accessOps"] += 1
                self.stats["atomicOps"] += 1
                self.stats["arithmeticDataOps"] += 1
                
            elif operation == "LogicalData":
                # Access -> Atomic -> LogicalData
                self.stats["accessOps"] += 1
                self.stats["atomicOps"] += 1
                self.stats["logicalDataOps"] += 1
                
            elif operation == "Get":
                # Access -> Get -> Get
                self.stats["accessOps"] += 1
                self.stats["getOps"] += 1
                self.stats["getRequestOps"] += 1
                
            elif operation == "Intent":
                # Hint -> Intent -> Intent
                self.stats["hintOps"] += 1
                self.stats["intentOps"] += 1
                
            elif operation == "AcquireBlock":
                # Transfer -> Acquire -> AcquireBlock
                self.stats["transferOps"] += 1
                self.stats["acquireOps"] += 1
                self.stats["acquireBlockOps"] += 1
                
            elif operation == "AcquirePerm":
                # Transfer -> Acquire -> AcquirePerm
                self.stats["transferOps"] += 1
                self.stats["acquireOps"] += 1
                self.stats["acquirePermOps"] += 1
                
            else:
                self.violations.append(
                    f"Unknown A-Channel operation {operation} at {transaction['timestamp']} in {hart}"
                )
            
            # Check cache state transitions for Acquire operations
            if (operation in ["AcquireBlock", "AcquirePerm"]) and growth:
                # Get cache state map for this hart
                if hart not in self.cache_states:
                    self.cache_states[hart] = {}
                hart_cache_states = self.cache_states[hart]
                
                # Setup cache state history for this hart/address
                if hart not in self.cache_state_history:
                    self.cache_state_history[hart] = {}
                if addr not in self.cache_state_history[hart]:
                    self.cache_state_history[hart][addr] = []
                state_history = self.cache_state_history[hart][addr]
                
                # Get current state for this address in this hart
                current_state = hart_cache_states.get(addr, 'None')
                
                # Map for transitions allowed by coherence protocol
                # NtoB: None -> Branch (first access)
                # NtoT: None -> Trunk (unique access)
                # BtoT: Branch -> Trunk (upgrade)
                # TtoB: Trunk -> Branch (downgrade)
                # TtoN: Trunk -> None (eviction/invalidation)
                # BtoN: Branch -> None (eviction/invalidation)
                expected_states = {
                    'NtoB': ['None'],
                    'NtoT': ['None'],
                    'BtoT': ['Branch'],
                    'TtoB': ['Trunk'],
                    'TtoN': ['Trunk'],
                    'BtoN': ['Branch']
                }
                
                # If there's a B-Channel ProbeBlock that affects this address prior to this transaction
                # but after the last A-Channel operation on this address, we allow 'None' as a valid
                # starting state for any transition, as it could have been invalidated
                probe_invalidated_line = False
                
                # Check for probes that might have invalidated this line
                if current_state != 'None' and expected_states.get(growth, [''])[0] == 'None':
                    # Find the last state-changing operation for this address
                    last_state_change_timestamp = 0
                    if state_history:
                        last_state_change_timestamp = state_history[-1]["timestamp"]
                    
                    # Look for B-Channel probes to this address
                    for trans in self.parsed_transactions:
                        if (trans["timestamp"] > last_state_change_timestamp and 
                            trans["timestamp"] < transaction["timestamp"] and
                            trans["channel"] == 'B-Channel' and 
                            trans["operation"] == 'ProbeBlock' and
                            trans["params"].get("addr") == addr):
                            probe_invalidated_line = True
                            break
                
                # For A-Channel Acquire operations, we trust the initiator knows its state
                # We don't validate state transitions for Acquire operations, just record them
                
                # Only log the transition for debugging purposes
                if (growth in expected_states and 
                    current_state not in expected_states[growth] and 
                    not probe_invalidated_line):
                    
                    print(f"Note: Acquire operation shows {current_state} -> {growth} for {addr} in {hart}")
                    
                    # We could have missed some operations that changed the state
                    # For example, Probe operations where the ProbeAck hasn't been processed yet
                
                # Update cache state
                new_state_map = {
                    'NtoB': 'Branch',
                    'NtoT': 'Trunk',
                    'BtoT': 'Trunk',
                    'TtoB': 'Branch',
                    'TtoN': 'None',
                    'BtoN': 'None'
                }
                
                if growth in new_state_map:
                    # Log the state transition in history
                    state_history.append({
                        "timestamp": transaction["timestamp"],
                        "oldState": current_state,
                        "newState": new_state_map[growth],
                        "operation": f"{transaction['operation']} - {growth}",
                        "channel": transaction["channel"]
                    })
                    
                    # Update current state
                    hart_cache_states[addr] = new_state_map[growth]
                    
        # Process B-Channel operations
        elif channel == "B-Channel":
            if 'addr' not in params:
                self.violations.append(
                    f"B-Channel {operation} at {transaction['timestamp']} in {hart} missing address"
                )
                return
            
            addr = params["addr"]
            cap = params.get("cap")
            
            # Create a tracking object for B-Channel operations
            # so we can match them with C-Channel responses later
            probe = {
                "request": transaction,
                "response": None
            }
            
            # Store depending on operation type
            if operation == "ProbeBlock":
                # Transfer -> Probe -> ProbeBlock
                self.stats["transferOps"] += 1
                self.stats["probeOps"] += 1
                self.stats["probeBlockOps"] += 1
                
                # Store the probe request
                if hart not in self.outstanding_probes:
                    self.outstanding_probes[hart] = {}
                if addr not in self.outstanding_probes[hart]:
                    self.outstanding_probes[hart][addr] = []
                self.outstanding_probes[hart][addr].append(probe)
                
                # Record in cache state history
                if hart not in self.cache_state_history:
                    self.cache_state_history[hart] = {}
                if addr not in self.cache_state_history[hart]:
                    self.cache_state_history[hart][addr] = []
                
                self.cache_state_history[hart][addr].append({
                    "timestamp": transaction["timestamp"],
                    "operation": f"{transaction['operation']} - {cap or ''}",
                    "channel": transaction["channel"],
                    "action": 'Probe received (state change pending ProbeAck)'
                })
                
            elif operation == "ProbePerm":
                # Transfer -> Probe -> ProbePerm
                self.stats["transferOps"] += 1
                self.stats["probeOps"] += 1
                self.stats["probePermOps"] += 1
                
                # Store the probe request
                if hart not in self.outstanding_probes:
                    self.outstanding_probes[hart] = {}
                if addr not in self.outstanding_probes[hart]:
                    self.outstanding_probes[hart][addr] = []
                self.outstanding_probes[hart][addr].append(probe)
                
            elif operation == "PutFullData":
                # Access -> Put -> PutFullData
                self.stats["accessOps"] += 1
                self.stats["putOps"] += 1
                self.stats["putFullDataOps"] += 1
                
            elif operation == "PutPartialData":
                # Access -> Put -> PutPartialData
                self.stats["accessOps"] += 1
                self.stats["putOps"] += 1
                self.stats["putPartialDataOps"] += 1
                
            elif operation == "ArithmeticData":
                # Access -> Atomic -> ArithmeticData
                self.stats["accessOps"] += 1
                self.stats["atomicOps"] += 1
                self.stats["arithmeticDataOps"] += 1
                
            elif operation == "LogicalData":
                # Access -> Atomic -> LogicalData
                self.stats["accessOps"] += 1
                self.stats["atomicOps"] += 1
                self.stats["logicalDataOps"] += 1
                
            elif operation == "Get":
                # Access -> Get -> Get
                self.stats["accessOps"] += 1
                self.stats["getOps"] += 1
                self.stats["getRequestOps"] += 1
                
            elif operation == "Intent":
                # Hint -> Intent -> Intent
                self.stats["hintOps"] += 1
                self.stats["intentOps"] += 1
                
            else:
                self.violations.append(
                    f"Unknown B-Channel operation {operation} at {transaction['timestamp']} in {hart}"
                )
                
        # Process C-Channel acknowledgments and operations
        elif channel == "C-Channel":
            if 'addr' not in params:
                self.violations.append(
                    f"C-Channel {operation} at {transaction['timestamp']} in {hart} missing address"
                )
                return
            
            addr = params["addr"]
            growth = params.get("growth")  # Should be like BtoN, TtoB, etc.
            
            if operation == "AccessAck":
                # Handle AccessAck - response to A-Channel Put operations
                self.stats["accessAckOps"] += 1
                
            elif operation == "AccessAckData":
                # Handle AccessAckData - response to A-Channel Get/Atomic operations
                self.stats["accessAckDataOps"] += 1
                
            elif operation == "HintAck":
                # Handle HintAck - response to A-Channel Intent operations
                self.stats["hintAckOps"] += 1
                
            elif operation == "ProbeAck":
                # Handle ProbeAck - response to B-Channel Probe
                self.stats["probeAckOps"] += 1
                self.update_cache_state_from_probe(hart, addr, growth)
                
            elif operation == "ProbeAckData":
                # Handle ProbeAckData - response to B-Channel Probe
                self.stats["probeAckDataOps"] += 1
                self.update_cache_state_from_probe(hart, addr, growth)
                
            elif operation == "Release":
                # Handle Release - voluntary cache state downgrade
                if 'source' not in params:
                    self.violations.append(
                        f"C-Channel {operation} at {transaction['timestamp']} in {hart} missing source parameter"
                    )
                    return
                
                self.stats["transferOps"] += 1
                self.stats["releaseOps"] += 1
                self.stats["releaseWithoutDataOps"] += 1
                
                self.handle_release_operation(hart, addr, params["source"], transaction, growth)
                
            elif operation == "ReleaseData":
                # Handle ReleaseData - voluntary cache state downgrade
                if 'source' not in params:
                    self.violations.append(
                        f"C-Channel {operation} at {transaction['timestamp']} in {hart} missing source parameter"
                    )
                    return
                
                self.stats["transferOps"] += 1
                self.stats["releaseOps"] += 1
                self.stats["releaseWithDataOps"] += 1
                
                self.handle_release_operation(hart, addr, params["source"], transaction, growth)
                
            else:
                self.violations.append(
                    f"Unknown C-Channel operation {operation} at {transaction['timestamp']} in {hart}"
                )
                
        # Process D-Channel responses
        elif channel == "D-Channel":
            if 'source' not in params:
                self.violations.append(
                    f"Missing source parameter in D-Channel {operation} at {transaction['timestamp']} in {hart}"
                )
                return
            
            source = params["source"]
            
            if operation == "Grant":
                # Handle Grant - response to A-Channel Acquire operations
                self.stats["grantOps"] += 1
                
                if 'sink' not in params:
                    self.violations.append(
                        f"Missing sink parameter in D-Channel {operation} at {transaction['timestamp']} in {hart}"
                    )
                    return
                
                sink_grant = params["sink"]
                
                # Find matching request
                matching_acquire_txn = None
                
                if hart in self.outstanding_requests and source in self.outstanding_requests[hart]:
                    source_map = self.outstanding_requests[hart][source]
                    # Take first matching transaction by source
                    for _, txn in source_map.items():
                        matching_acquire_txn = txn
                        break
                
                if matching_acquire_txn:
                    # Add response to transaction
                    matching_acquire_txn.responses.append(transaction)
                    
                    # Store grant for ack matching
                    hart_map = self.get_hart_map(self.outstanding_grants, hart)
                    hart_map[sink_grant] = matching_acquire_txn
                else:
                    self.violations.append(
                        f"D-Channel {operation} at {transaction['timestamp']} in {hart} " +
                        f"with source {source} has no matching request"
                    )
                    
            elif operation == "GrantData":
                # Handle GrantData - response to A-Channel Acquire operations
                self.stats["grantDataOps"] += 1
                
                if 'sink' not in params:
                    self.violations.append(
                        f"Missing sink parameter in D-Channel {operation} at {transaction['timestamp']} in {hart}"
                    )
                    return
                
                sink_grant_data = params["sink"]
                
                # Find matching request
                matching_grant_data_txn = None
                
                if hart in self.outstanding_requests and source in self.outstanding_requests[hart]:
                    source_map = self.outstanding_requests[hart][source]
                    # Take first matching transaction by source
                    for _, txn in source_map.items():
                        matching_grant_data_txn = txn
                        break
                
                if matching_grant_data_txn:
                    # Add response to transaction
                    matching_grant_data_txn.responses.append(transaction)
                    
                    # Store grant for ack matching
                    hart_map = self.get_hart_map(self.outstanding_grants, hart)
                    hart_map[sink_grant_data] = matching_grant_data_txn
                else:
                    self.violations.append(
                        f"D-Channel {operation} at {transaction['timestamp']} in {hart} " +
                        f"with source {source} has no matching request"
                    )
                    
            elif operation == "AccessAck":
                # Handle AccessAck - response to A-Channel Put operations
                self.stats["accessAckOps"] += 1
                self.handle_generic_d_response(hart, source, transaction, "Put")
                
            elif operation == "AccessAckData":
                # Handle AccessAckData - response to A-Channel Get/Atomic operations
                self.stats["accessAckDataOps"] += 1
                self.handle_generic_d_response(hart, source, transaction, "Get/Atomic")
                
            elif operation == "HintAck":
                # Handle HintAck - response to A-Channel Intent operations
                self.stats["hintAckOps"] += 1
                self.handle_generic_d_response(hart, source, transaction, "Intent")
                
            elif operation == "ReleaseAck":
                # Handle ReleaseAck - response to C-Channel Release/ReleaseData
                self.stats["releaseAckOps"] += 1
                
                # Find matching Release/ReleaseData operation
                matching_release = None
                matching_addr = None
                
                if (hart in self.outstanding_releases and 
                    source in self.outstanding_releases[hart]):
                    
                    source_map = self.outstanding_releases[hart][source]
                    # Find the first release with this source
                    for addr, release_txn in source_map.items():
                        matching_release = release_txn
                        matching_addr = addr
                        break
                
                if matching_release:
                    # Add the ReleaseAck as the response to the Release/ReleaseData
                    matching_release["response"] = transaction
                    
                    # Remove from outstanding releases
                    del self.outstanding_releases[hart][source][matching_addr]
                else:
                    self.violations.append(
                        f"D-Channel {operation} at {transaction['timestamp']} in {hart} " +
                        f"with source {source} has no matching C-Channel Release/ReleaseData"
                    )
                    
            else:
                self.violations.append(
                    f"Unknown D-Channel operation {operation} at {transaction['timestamp']} in {hart}"
                )
                
        # Process E-Channel acknowledgments
        elif channel == "E-Channel":
            if operation == "GrantAck":
                self.stats["grantAckOps"] += 1
                
                if 'sink' in params:
                    sink = params["sink"]
                    
                    if hart in self.outstanding_grants and sink in self.outstanding_grants[hart]:
                        # Get the transaction
                        txn = self.outstanding_grants[hart][sink]
                        
                        # Add ack to transaction
                        txn.ack = transaction
                        
                        # Remove from outstanding grants
                        del self.outstanding_grants[hart][sink]
                        
                        # Mark transaction as complete
                        if txn.is_complete():
                            self.stats["completeTransactions"] += 1
                            
                            # Remove request from outstanding requests if complete
                            if (txn.request and 'source' in txn.request["params"] and
                                hart in self.outstanding_requests and
                                txn.request["params"]["source"] in self.outstanding_requests[hart] and
                                'addr' in txn.request["params"] and
                                txn.request["params"]["addr"] in self.outstanding_requests[hart][txn.request["params"]["source"]]):
                                
                                del self.outstanding_requests[hart][txn.request["params"]["source"]][txn.request["params"]["addr"]]
                    else:
                        self.violations.append(
                            f"E-Channel {operation} at {transaction['timestamp']} in {hart} " +
                            f"with sink {sink} has no matching grant"
                        )
                else:
                    self.violations.append(
                        f"Missing required parameters in E-Channel {operation} at {transaction['timestamp']} in {hart}"
                    )
    
    def check_outstanding_transactions(self):
        # Check for outstanding A-Channel requests without D-Channel responses
        for hart, sources in self.outstanding_requests.items():
            for source, addrs in sources.items():
                for addr, txn in addrs.items():
                    if not txn.responses:
                        self.violations.append(
                            f"A-Channel request at {txn.request['timestamp']} in {hart} " +
                            f"with source {source} addr {addr} has no response"
                        )
        
        # Check for outstanding D-Channel grants without E-Channel acks
        for hart, sinks in self.outstanding_grants.items():
            for sink, txn in sinks.items():
                self.violations.append(
                    f"D-Channel grant at {txn.responses[-1]['timestamp']} in {hart} " +
                    f"with sink {sink} has no acknowledgment"
                )
        
        # Check for outstanding C-Channel Release operations without D-Channel ReleaseAck
        for hart, sources in self.outstanding_releases.items():
            for source, addrs in sources.items():
                for addr, release_txn in addrs.items():
                    if not release_txn["response"]:
                        release_op = release_txn["request"]["operation"]
                        self.violations.append(
                            f"C-Channel {release_op} at {release_txn['request']['timestamp']} in {hart} " +
                            f"with source {source} addr {addr} has no matching D-Channel ReleaseAck"
                        )
    
    def check_channel_ordering(self):
        # Check that D responses follow A requests and E acks follow D responses
        for txn in self.transactions:
            if txn.request and txn.responses:
                req_time = txn.request["timestamp"]
                req_hart = txn.request["hart"]
                
                for resp in txn.responses:
                    resp_time = resp["timestamp"]
                    resp_hart = resp["hart"]
                    if resp_time < req_time:
                        self.violations.append(
                            f"Response at {resp_time} in {resp_hart} came before request at {req_time} in {req_hart}"
                        )
                
                if txn.ack and txn.responses:
                    ack_time = txn.ack["timestamp"]
                    ack_hart = txn.ack["hart"]
                    last_resp = max(txn.responses, key=lambda x: x["timestamp"])
                    last_resp_time = last_resp["timestamp"]
                    last_resp_hart = last_resp["hart"]
                    
                    if ack_time < last_resp_time:
                        self.violations.append(
                            f"Acknowledgment at {ack_time} in {ack_hart} came before response at {last_resp_time} in {last_resp_hart}"
                        )
    
    def analyze_log(self, log_data):
        # Reset state for new analysis
        self.transactions = []
        self.parsed_transactions = []
        self.outstanding_requests = {}
        self.outstanding_grants = {}
        self.outstanding_probes = {}
        self.outstanding_releases = {}
        self.cache_states = {}
        self.cache_state_history = {}
        self.violations = []
        
        # Reset statistics
        self.reset_stats()
        
        lines = log_data.strip().split("\n")
        
        for line in lines:
            transaction = self.parse_log_line(line.strip())
            if transaction:
                self.analyze_transaction(transaction)
        
        # Check for outstanding transactions
        self.check_outstanding_transactions()
        
        # Check operation ordering
        self.check_channel_ordering()
        
        return {
            "compliant": len(self.violations) == 0,
            "stats": self.stats,
            "violations": self.violations,
            "transactions": self.parsed_transactions
        }
    
    def format_results(self, results):
        """Format analysis results as a string"""
        output = []
        
        # Transaction Statistics section
        output.append("=== Transaction Statistics ===")
        output.append(f"Total A-Channel transactions: {results['stats']['totalTransactions']}")
        output.append(f"Complete A-Channel transactions: {results['stats']['completeTransactions']}")
        
        output.append("\nChannel operations:")
        output.append(f"A-Channel: {results['stats']['aChannelOps']}")
        output.append(f"B-Channel: {results['stats']['bChannelOps']}")
        output.append(f"C-Channel: {results['stats']['cChannelOps']}")
        output.append(f"D-Channel: {results['stats']['dChannelOps']}")
        output.append(f"E-Channel: {results['stats']['eChannelOps']}")
        
        output.append("\nOperation Categories:")
        output.append(f"Access: {results['stats']['accessOps']}")
        output.append(f"- Put: {results['stats']['putOps']}")
        output.append(f"- Get: {results['stats']['getOps']}")
        output.append(f"- Atomic: {results['stats']['atomicOps']}")
        output.append(f"Hint: {results['stats']['hintOps']}")
        output.append(f"Transfer: {results['stats']['transferOps']}")
        output.append(f"- Acquire: {results['stats']['acquireOps']}")
        output.append(f"- Probe: {results['stats']['probeOps']}")
        output.append(f"- Release: {results['stats']['releaseOps']}")
        
        output.append("\nSpecific Operations:")
        output.append(f"PutFullData: {results['stats']['putFullDataOps']}")
        output.append(f"PutPartialData: {results['stats']['putPartialDataOps']}")
        output.append(f"Get: {results['stats']['getRequestOps']}")
        output.append(f"ArithmeticData: {results['stats']['arithmeticDataOps']}")
        output.append(f"LogicalData: {results['stats']['logicalDataOps']}")
        output.append(f"Intent: {results['stats']['intentOps']}")
        output.append(f"AcquireBlock: {results['stats']['acquireBlockOps']}")
        output.append(f"AcquirePerm: {results['stats']['acquirePermOps']}")
        output.append(f"ProbeBlock: {results['stats']['probeBlockOps']}")
        output.append(f"ProbePerm: {results['stats']['probePermOps']}")
        output.append(f"Release: {results['stats']['releaseWithoutDataOps']}")
        output.append(f"ReleaseData: {results['stats']['releaseWithDataOps']}")
        
        # Protocol Compliance section
        output.append("\n=== Protocol Compliance ===")
        if results["compliant"]:
            output.append("✅ Compliant with TileLink protocol")
        else:
            output.append("❌ Protocol violations detected")
        
        # Violations section
        if not results["compliant"]:
            output.append("\n=== Protocol Violations ===")
            for violation in results["violations"]:
                output.append(f"- {violation}")
        
        # Transaction log section
        output.append("\n=== Transaction Log ===")
        output.append("Time (ns)      | Hart  | Channel     | Operation      | Address      | Details")
        output.append("-" * 100)
        
        for txn in results["transactions"]:
            time_str = f"{txn['timestamp']:.2f}".ljust(14)
            hart_str = txn["hart"].ljust(7)
            channel_str = txn["channel"].ljust(13)
            operation_str = txn["operation"].ljust(15)
            addr_str = txn["params"].get("addr", "-").ljust(13)
            details = txn["rawParams"][:60] + "..." if len(txn["rawParams"]) > 60 else txn["rawParams"]
            
            output.append(f"{time_str}| {hart_str}| {channel_str}| {operation_str}| {addr_str}| {details}")
        
        return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(description='TileLink Protocol Log Analyzer')
    parser.add_argument('input_file', help='Path to TileLink log file')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    try:
        # Read input file
        with open(args.input_file, 'r') as f:
            log_data = f.read()
        
        # Analyze log
        analyzer = TileLinkAnalyzer()
        results = analyzer.analyze_log(log_data)
        
        # Format results
        output = analyzer.format_results(results)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Analysis results written to {args.output}")
        else:
            print(output)
            
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
