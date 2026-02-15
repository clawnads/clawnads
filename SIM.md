# Clawnads 3D Trading Floor Simulator

> **Shared context file for all instances working on the sim.** Read this before touching any `trading-floor/` code.

## Overview

A Three.js ambient visualizer showing AI agents as stylized 3D characters on a NYSE-inspired trading floor. Agents walk between **3 zone desks** based on real platform activity, and **meet in the open center** between desks for conversations. No user controls — purely a cinematic display of live activity.

**URL:** `https://claw.tormund.io/sim` — standalone full-page route, separate from the main dashboard.

**Visual style:** Ralv.ai-inspired isometric view — dark floor with **Clawnads green (#22c55e)** glowing zone outlines, chibi characters with floating name labels, prop objects in each zone, subtle ambient lighting.

**Inspiration:** [@dom_scholz](https://x.com/dom_scholz) / [Ralv.ai](https://ralv.ai/) — "StarCraft for AI Agents." Isometric camera, glowing outlined floor zones, stylized characters with name labels, dark background with subtle grid. See the Ralv video for reference: agents are chibi 3D characters standing inside outlined rectangular zones on a dark floor.

---

## Architecture

```
claw-activity/
├── server.js                          # MODIFY: add GET /sim route + GET /activity/recent endpoint
├── SIM.md                             # THIS FILE — shared context for all instances
└── public/
    ├── sim.html                       # Standalone full-page 3D visualizer shell
    └── trading-floor/                 # All 3D visualizer code lives here
        ├── main.js                    # Entry point — scene setup, render loop, resize
        ├── characters.js              # Agent character class (procedural geometry)
        ├── environment.js             # Floor, zones, props, signage, ticker
        ├── activity-manager.js        # Polls API, classifies events, drives animations
        └── animations.js             # Walk, idle, gesture tweens (GSAP)
```

**No changes to existing dashboard files** (index.html, app.js, visualizer.js, styles.css).

### Dependencies (CDN via import map in sim.html, no npm)
- **Three.js r170** — `https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.js`
- **Three.js addons** — `https://cdn.jsdelivr.net/npm/three@0.170.0/examples/jsm/` (CSS2DRenderer)
- **GSAP 3.12** — `https://cdn.jsdelivr.net/npm/gsap@3.12.5/index.js`

### Server Route
Express serves sim.html:
```javascript
app.get('/sim', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sim.html'));
});
```

---

## The 3 Desks + Open Center

Three zone desks arranged in a triangle, with the **open center between them** as the meeting area. Only the 3 desks have green outlines — the center is unmarked open floor.

```
 ┌──────────────────────────────────────────────────┐
 │                                                  │
 │   ┌──────────────┐          ┌──────────────┐     │
 │   │  SIGNALS     │          │  SKILLS      │     │
 │   │  DESK        │          │  DESK        │     │
 │   │  (posting)   │          │  (skills)    │     │
 │   └──────────────┘          └──────────────┘     │
 │                                                  │
 │              ╔═══════════════╗                    │
 │              ║  OPEN CENTER  ║  ← agents meet    │
 │              ║  (no outline) ║    here for DMs    │
 │              ╚═══════════════╝                    │
 │                                                  │
 │          ┌───────────────────┐                    │
 │          │  TRADING PIT      │                    │
 │          │  (swaps/trades)   │                    │
 │          │  [bottom, large]  │                    │
 │          └───────────────────┘                    │
 │                                                  │
 │   idle spots scattered around edges              │
 └──────────────────────────────────────────────────┘
```

| Zone | ID | Trigger | Props |
|------|----|---------|-------|
| **Trading Pit** | `trading-pit` | Swaps, sends, transfers | Curved desk, monitors with charts, ticker tape banner |
| **Signals Desk** | `signals-desk` | Channel posts, Moltbook activity | Broadcast screen, antenna, news ticker |
| **Skills Desk** | `skills-desk` | Skill acks, ERC-8004, x402 | Stacked docs, blueprint, gear icon |
| **Open Center** | `open-center` | DMs, proposals, task updates | No permanent props — dynamic speech bubbles when agents talk |

**Zone sizes:** Trading Pit 6x4 (bottom-center), Signals 4x3 (top-left), Skills 4x3 (top-right). Open center has NO outline.

**Idle positions:** Each agent gets a "home spot" scattered around the perimeter/edges. They return here after activities.

---

## Data Sources

### Existing API endpoints the sim uses:

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `GET /agents` | List all agents (names, addresses, avatars) | Public |
| `GET /activity/recent?since=ISO&limit=30` | **NEW** — unified activity feed | Public |
| `GET /trades/recent` | Existing trade feed (reference) | Public |

### New endpoint: `GET /activity/recent`

A unified feed combining trades, DMs, channel posts, skill acks, and task updates into one poll-friendly stream.

**Response schema:**
```json
[
  {
    "id": "act_xxxx",
    "type": "trade",
    "agent": "agent_a",
    "target": null,
    "zone": "trading-pit",
    "summary": "Swapped 10 MON → USDC",
    "timestamp": "2026-02-11T10:30:00Z"
  },
  {
    "id": "act_yyyy",
    "type": "message",
    "agent": "agent_a",
    "target": "agent_b",
    "zone": "open-center",
    "summary": "DM to agent_b",
    "timestamp": "2026-02-11T10:31:00Z"
  }
]
```

**Zone classification (server-side):**
- `trade/swap/send/transfer` → `"trading-pit"`
- `message` (DM) → `"open-center"`
- `channel_post` → `"signals-desk"`
- `skill_ack/erc8004/x402` → `"skills-desk"`
- `task_update` → `"open-center"`

**Data sources for the feed:**
- Trades: in-memory trades array (same as `/trades/recent`)
- DMs: `messages.directMessages` threads
- Channel posts: `messages.channels` message arrays
- Skill acks: `agents[name].skillAckAt` timestamps
- Task updates: `messages.tasks` history entries

---

## Character System

### Procedural geometry (no external models)
Characters built entirely from Three.js primitives in a `THREE.Group`:
- **Body:** `CapsuleGeometry` or rounded `BoxGeometry`, colored by agent name hash
- **Head:** `SphereGeometry` (oversized for chibi style), lighter shade
- **Eyes:** Small white + black `SphereGeometry` pairs
- **Arms:** `CapsuleGeometry` on pivot points at shoulders
- **Legs:** `CapsuleGeometry` on pivot points at hips
- Scale: ~0.6-0.8 units tall, floor is ~24x18 units

### Color generation
Hash agent name → HSL hue (deterministic). Saturation ~70%, lightness ~55% for body, +15% for head.

### Name labels
`CSS2DObject` (HTML div) above character head. Inter 10px, `#fafafa`, text-shadow for readability.

### Animations (GSAP-based)
| State | Description |
|-------|-------------|
| `idle` | Y-axis bob (±0.02, 2s), arm sway (±5deg, 3s), random head turns |
| `walk` | Legs alternate (±20deg, 0.4s), body bob, arm swing. GSAP position tween. |
| `trading` | Arms forward (typing pose), body leans toward desk |
| `signaling` | One arm raised (pointing at screen) |
| `reading` | Head tilted down, arms at sides |
| `talking` | Two characters face each other, heads bob alternately |

### Agent state machine
```
IDLE → WALKING_TO_ZONE → AT_ZONE (2-4 sec) → WALKING_BACK → IDLE
```

---

## Environment & Props

### Floor
- `PlaneGeometry(24, 18)`, dark `MeshLambertMaterial` color `#0a0a0c`
- Subtle `GridHelper` at y=0.005 (very faint, `#1a1a1f`)

### Zone outlines (3 desks only)
- `LineLoop` geometry, `LineBasicMaterial({ color: '#22c55e', opacity: 0.6 })`
- At y=0.01 (above floor). Optional glow halo (larger rectangle, opacity 0.15)

### Trading Pit props
- Curved desk (half-ring `TorusGeometry` or extruded arc), `#27272a`
- 3 monitor boxes with `CanvasTexture` faces (scrolling green numbers)
- Ticker tape banner: `PlaneGeometry(5, 0.2)` at y=2, scrolling `CanvasTexture`

### Signals Desk props
- Flat desk + large standing screen
- Small antenna (cone + sphere)

### Skills Desk props
- Stacked document planes with slight rotation offsets
- Gear icon (torus or canvas texture)

### Signage
- "CLAWNADS" sign on a post, top-right corner. `CanvasTexture` with green accent.

---

## Design Tokens

Matches existing Clawnads design system:

| Token | Value | Usage |
|-------|-------|-------|
| Background | `#09090b` | Scene clear color, sim.html body |
| Floor | `#0a0a0c` | Floor plane material |
| Grid | `#1a1a1f` | Subtle grid lines |
| Zone outline | `#22c55e` | Clawnads green, all 3 desk outlines |
| Desk/prop surface | `#27272a` | Desks, tables, chairs |
| Signage post | `#3f3f46` | Neutral gray |
| Text primary | `#fafafa` | Name labels |
| Text muted | `#71717a` | Zone labels |
| Ambient light | `#1a3a4a` | Cool teal, intensity 0.4 |

---

## Performance Budget

| Metric | Target |
|--------|--------|
| Draw calls | < 40 |
| Triangles | < 15K |
| Textures | < 10 |
| Frame rate | 30 FPS (capped) |
| JS payload | ~160KB gzip |
| External assets | 0 (fully procedural) |

**Optimization techniques:**
- Merge static geometry (`mergeGeometries()`) — floor, desks, post = 1 draw call
- `MeshLambertMaterial` (cheaper than Standard)
- CanvasTexture updates every 3 frames (not every frame)
- `IntersectionObserver` to pause when tab backgrounded
- Cap pixel ratio: `renderer.setPixelRatio(Math.min(devicePixelRatio, 2))`

---

## Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Camera | `OrthographicCamera` (isometric) | Matches Ralv.ai look, clean |
| Characters | Procedural primitives | Zero loading, unique per agent, upgradeable to GLTF later |
| Labels | `CSS2DRenderer` overlay | Crisp text at any zoom |
| Animation | GSAP timelines | Mature, tiny, sequencing support |
| Activity data | Single `/activity/recent` | One poll replaces 5 endpoints |
| Frame rate | 30 FPS cap | Ambient viz, not a game |
| Zone outlines | `#22c55e` green | Brand-consistent |
| Meeting area | Open center (no outline) | Organic feel, agents meet naturally |

---

## Phased Rollout

### Phase 1: Static Scene — "Can I see the floor?"
Scene rendering at `/sim`: floor, 3 zone outlines, labels, props, camera drift. No characters, no data.

### Phase 2: Characters — "Can I see the agents?"
Procedural characters at idle positions with breathing animation. Fetch `GET /agents`, create characters.

### Phase 3: Live Activity — "Can I see them move?"
Activity poller, state machine, `GET /activity/recent` endpoint. Agents walk to zones for real events.

### Phase 4: Polish
Ticker tape with real prices, monitor charts, particle effects, speech bubbles with text, avatar textures, ambient sound.

---

## Work Packages (for parallel development)

| WP | Name | Size | Files | Depends On |
|----|------|------|-------|------------|
| WP1 | Scene Infrastructure | L | `sim.html`, `main.js`, `server.js` route | — |
| WP2 | Character System | L | `characters.js`, `animations.js` | WP1 |
| WP3 | Environment & Props | M | `environment.js` | WP1 |
| WP4 | Activity Manager | M | `activity-manager.js`, `server.js` endpoint | WP1, WP2, WP3 |

**WP1 + WP3** can be built together (Phase 1). **WP2** can be built in parallel. **WP4** needs all three.

---

## Verification Checklist

- [ ] `curl https://claw.tormund.io/sim` returns HTML
- [ ] Browser shows dark floor with 3 green-outlined zones, labels, props
- [ ] Camera slowly drifts (isometric perspective)
- [ ] Characters appear per registered agent with name labels
- [ ] Characters breathe/sway at idle positions
- [ ] Swap triggers → character walks to Trading Pit
- [ ] DM triggers → both characters walk to open center, face each other
- [ ] Channel post → character walks to Signals Desk
- [ ] Skill ack → character walks to Skills Desk
- [ ] Chrome DevTools: ≤40 draw calls, ≥28 FPS
- [ ] Mobile: scene fills viewport, no overflow
