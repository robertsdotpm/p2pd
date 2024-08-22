INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2

def tcp_puncher_states(dest_mappings, state):
    # bool of dest_mappings, start state, to state.
    progressions = [
        [False, None, INITIATED_PREDICTIONS],
        [True, None, RECEIVED_PREDICTIONS],
        [True, INITIATED_PREDICTIONS, UPDATED_PREDICTIONS]
    ]

    # What protocol 'side' corresponds to a state.
    sides = {
        INITIATED_PREDICTIONS: INITIATOR,
        UPDATED_PREDICTIONS: INITIATOR,
        RECEIVED_PREDICTIONS: RECIPIENT,
    }

    # Progress the state machine.
    for progression in progressions:
        from_recv, from_state, to_state = progression
        if from_recv != bool(dest_mappings):
            continue

        if from_state != state:
            continue

        return to_state, sides[to_state]
    
    raise Exception("Invalid puncher state progression.")

def get_nat_predictions(a, b, c, d, e):
    pass