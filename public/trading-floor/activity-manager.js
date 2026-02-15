// Clawnads 3D Trading Floor — Activity Manager
// Polls /activity/recent, classifies events, drives agent state machines

const POLL_INTERVAL = 5000; // 5 seconds
const ACTIVITY_DURATION = 3.0; // seconds at zone before walking back
const MAX_SIMULTANEOUS = 3; // max agents animating at once
const MAX_EVENT_AGE = 60000; // drop events older than 60s when dequeued

// Agent states
const STATE = {
  IDLE: 'idle',
  WALKING_TO: 'walking_to',
  AT_ZONE: 'at_zone',
  WALKING_BACK: 'walking_back'
};

// Map zone to animation type
const ZONE_ACTIVITY = {
  'trading-pit': 'trading',
  'signals-desk': 'signaling',
  'skills-desk': 'reading',
  'open-center': 'talking'
};

// Emoji for activity types
const TYPE_EMOJI = {
  'trade': '📊',
  'swap': '📊',
  'send': '💸',
  'transfer': '💸',
  'message': '💬',
  'channel_post': '📡',
  'skill_ack': '🔧',
  'erc8004': '🪪',
  'x402': '✅',
  'task_update': '📋'
};

function formatBubbleText(event) {
  const emoji = TYPE_EMOJI[event.type] || '⚡';
  const summary = event.summary || event.type || 'active';
  // Truncate long summaries
  const short = summary.length > 24 ? summary.slice(0, 22) + '…' : summary;
  return `${emoji} ${short}`;
}

export class ActivityManager {
  constructor(tradingFloor) {
    this.floor = tradingFloor;
    this.pollTimer = null;
    this.lastTimestamp = null;
    this.eventQueue = []; // global FIFO
    this.agentStates = new Map(); // name → { state, zone, timer, homePos, queuedEvents }
    this.activeAnimations = 0;
  }

  start() {
    // Initial fetch with a few recent events to seed the scene
    this._poll(true);
    this.pollTimer = setInterval(() => this._poll(), POLL_INTERVAL);
  }

  stop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  // --- Polling ---

  async _poll(initial = false) {
    try {
      let url = '/activity/recent?limit=30';
      if (this.lastTimestamp && !initial) {
        url += `&since=${encodeURIComponent(this.lastTimestamp)}`;
      } else if (initial) {
        url += '&limit=5'; // just a few to seed
      }

      const res = await fetch(url);
      if (!res.ok) return;

      const events = await res.json();
      if (!Array.isArray(events) || events.length === 0) return;

      // Update last timestamp
      const newest = events[0]; // sorted desc
      if (newest && newest.timestamp) {
        this.lastTimestamp = newest.timestamp;
      }

      // Queue events (oldest first)
      const sorted = events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      for (const event of sorted) {
        this._queueEvent(event);
      }
    } catch (err) {
      // Silent fail — polling will retry
    }
  }

  _queueEvent(event) {
    // Only queue events for agents that are already loaded (verified)
    // Don't auto-create characters for unknown agents
    if (event.agent && !this.floor.characters.has(event.agent)) {
      return; // skip — agent not verified / not loaded
    }

    this.eventQueue.push(event);
  }

  // --- State machine tick (called every frame) ---

  tick(delta) {
    // Pause activity animations while dancing
    if (this.floor._isDancing) return;

    // Process agent timers
    for (const [name, state] of this.agentStates) {
      if (state.state === STATE.AT_ZONE) {
        state.timer -= delta;
        if (state.timer <= 0) {
          this._walkBack(name);
        }
      }
    }

    // Try to dequeue and start new animations
    this._processQueue();
  }

  _processQueue() {
    while (this.eventQueue.length > 0 && this.activeAnimations < MAX_SIMULTANEOUS) {
      const event = this.eventQueue.shift();

      // Drop stale events
      if (Date.now() - new Date(event.timestamp).getTime() > MAX_EVENT_AGE) {
        continue;
      }

      const agentName = event.agent;
      if (!agentName) continue;

      // Skip if agent is already busy
      const agentState = this.agentStates.get(agentName);
      if (agentState && agentState.state !== STATE.IDLE) {
        // Re-queue for later (put at front)
        this.eventQueue.unshift(event);
        break; // try again next tick
      }

      this._startActivity(event);
    }
  }

  _startActivity(event) {
    const agentName = event.agent;
    const zone = event.zone || 'trading-pit';
    const character = this.floor.getCharacter(agentName);
    if (!character) return;

    const env = this.floor.environment;
    const waitSpotIndex = this.activeAnimations % 5;
    const target = env.getZoneWaitSpot(zone, waitSpotIndex);

    // Save home position
    const homePos = character.getPosition();
    const state = {
      state: STATE.WALKING_TO,
      zone,
      timer: ACTIVITY_DURATION,
      homePos,
      event
    };
    this.agentStates.set(agentName, state);
    this.activeAnimations++;

    // Stop idle bubble cycle, show live activity bubble
    character.stopIdleBubbleCycle();
    const bubbleText = formatBubbleText(event);
    character.showBubble(bubbleText, 0); // 0 = don't auto-dismiss while active

    // Walk to zone
    character.walkTo(target.x, target.z, () => {
      // Arrived at zone
      state.state = STATE.AT_ZONE;
      const activityType = ZONE_ACTIVITY[zone] || 'trading';

      // Face toward zone center for context
      const center = env.getZoneCenter(zone);
      character.faceToward(center.x, center.z);
      character.playActivity(activityType);

      // For DMs — also move the target agent
      if (event.target && zone === 'open-center') {
        this._moveTargetAgent(event);
      }
    });
  }

  _moveTargetAgent(event) {
    const targetName = event.target;
    const targetChar = this.floor.getCharacter(targetName);
    if (!targetChar) return;

    // Check if target is already busy
    const targetState = this.agentStates.get(targetName);
    if (targetState && targetState.state !== STATE.IDLE) return;

    const env = this.floor.environment;
    const target = env.getZoneWaitSpot('open-center', 1); // second spot in center
    const homePos = targetChar.getPosition();

    const state = {
      state: STATE.WALKING_TO,
      zone: 'open-center',
      timer: ACTIVITY_DURATION,
      homePos,
      event
    };
    this.agentStates.set(targetName, state);
    this.activeAnimations++;

    targetChar.stopIdleBubbleCycle();
    targetChar.showBubble(`💬 chat with ${event.agent}`, 0);

    targetChar.walkTo(target.x, target.z, () => {
      state.state = STATE.AT_ZONE;
      // Face toward the initiating agent
      const initiatorChar = this.floor.getCharacter(event.agent);
      if (initiatorChar) {
        const pos = initiatorChar.getPosition();
        targetChar.faceToward(pos.x, pos.z);
      }
      targetChar.playActivity('talking');
    });
  }

  _walkBack(name) {
    const state = this.agentStates.get(name);
    if (!state) return;

    const character = this.floor.getCharacter(name);
    if (!character) {
      this.agentStates.delete(name);
      this.activeAnimations = Math.max(0, this.activeAnimations - 1);
      return;
    }

    state.state = STATE.WALKING_BACK;

    // Dismiss the active bubble
    character._dismissBubble();

    // Update last activity text for future idle cycle
    if (state.event) {
      character.setLastActivity(formatBubbleText(state.event));
    }

    character.walkTo(state.homePos.x, state.homePos.z, () => {
      state.state = STATE.IDLE;
      this.agentStates.delete(name);
      this.activeAnimations = Math.max(0, this.activeAnimations - 1);
      character.playIdle();
    });
  }
}
