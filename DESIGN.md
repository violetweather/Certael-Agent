---
name: Certael Agent
description: A calm, truthful checkpoint for protected game launch.
colors:
  canvas: "#0B121B"
  surface: "#111C28"
  raised: "#182534"
  border: "#2A3A4C"
  primary-ink: "#F4F7FA"
  secondary-ink: "#A8B5C4"
  muted-ink: "#7D8C9E"
  assurance: "#58C7D4"
  focus: "#78DCE6"
  recovery: "#FFB4A9"
  action: "#286873"
typography:
  headline:
    fontFamily: "egui Proportional, sans-serif"
    fontSize: "27px"
    fontWeight: 600
  title:
    fontFamily: "egui Proportional, sans-serif"
    fontSize: "23px"
    fontWeight: 600
  body:
    fontFamily: "egui Proportional, sans-serif"
    fontSize: "15px"
    fontWeight: 400
  label:
    fontFamily: "egui Proportional, sans-serif"
    fontSize: "13px"
    fontWeight: 400
rounded:
  control: "3px"
  artwork: "6px"
  identity: "8px"
spacing:
  compact: "10px"
  standard: "12px"
  section: "20px"
  frame: "28px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.control}"
    padding: "11px 18px"
    height: "46px"
  button-secondary:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.control}"
    padding: "11px 18px"
    height: "46px"
---

# Design System: Certael Agent

## 1. Overview

**Creative North Star: "The Quiet Checkpoint"**

Certael Agent is a wide native launch window that lets verified game identity and signed publisher artwork carry the opening moment. Beneath that artwork, a three-stage rail tells the truth about checks, launch, and authoritative server admission. The surface is cinematic without behaving like marketing: it exists to explain a security boundary during a short wait.

The layout is calm, flat, and direct. At large text scales the decorative hero yields to the launch explanation; on failure it disappears entirely so recovery becomes the only task. It rejects neon security theater, alarm-heavy red dashboards, fake progress, premature “Protected” claims, glassmorphism, generic card grids, marketing-page composition, and unexplained risk graphics.

**Key Characteristics:**

- Full-width, publisher-signed game artwork at normal desktop scales
- One horizontal, semantically ordered progress rail
- Dark-only restrained palette with a rare cyan assurance signal
- Plain-language active and failure states driven by real runtime milestones
- Native controls, AccessKit semantics, and 200% text reflow

## 2. Colors

Deep blue-black surfaces frame game artwork without competing with it. Cyan is a functional assurance signal, not decoration; soft coral marks recovery without turning the window into an alarm.

### Primary

- **Calm Assurance:** Marks completed checks, the active milestone, and keyboard focus.
- **Bounded Action:** Fills the primary recovery control.

### Secondary

- **Recovery Coral:** Identifies the failed milestone using both color and an exclamation mark.

### Neutral

- **Checkpoint Canvas:** Owns the full window background.
- **Verification Surface and Raised Control:** Separate native controls through tone rather than shadow.
- **Primary, Secondary, and Muted Ink:** Establish the state, explanation, and supporting-copy hierarchy. Every text token passes 4.5:1 contrast on the canvas.
- **Structural Border:** Draws pending rail segments and quiet separators.

**The One Signal Rule.** Assurance cyan appears only on active, completed, focused, or successful elements.

**The Meaning Beyond Color Rule.** Every state also has position, text, and a distinct check, dot, ring, or exclamation mark.

## 3. Typography

**Display Font:** egui Proportional with the bundled native-safe sans fallback

**Body Font:** egui Proportional with the bundled native-safe sans fallback

**Character:** One clear humanist-leaning sans keeps security explanations familiar and avoids font-loading or platform-substitution surprises.

### Hierarchy

- **Headline** (semibold, 27px): Failure outcome only.
- **Title** (semibold, 23–25px): Verified game identity and active launch state.
- **Body** (regular, 15–18px): Explanations and actionable failure copy.
- **Label** (regular/semibold, 13–14px): Milestones, publisher identity, footer, and controls.

**The Plain Language Rule.** Player-facing copy states what is happening and who confirms it. Internal reason codes are mapped to explanations and never shown as the primary message.

## 4. Elevation

The content is flat. Tonal layers and thin separators establish structure; the operating system may draw the only window shadow. Artwork, rail, and explanation remain one surface rather than a stack of cards.

**The Single Window Rule.** Never place cards, glass panels, or modal surfaces inside the launch splash.

## 5. Components

### Buttons

- **Shape:** Restrained native corners (3px) and a minimum 46px height.
- **Primary:** Bounded-action teal with high-contrast primary ink and a 2px focus-colored boundary.
- **Hover / Focus:** The same assurance family strengthens the boundary; keyboard operation uses native egui focus and AccessKit actions.
- **Secondary:** Raised neutral fill for offline play and close.

### Cards / Containers

- **Corner Style:** Artwork uses a restrained 6px crop; the verified icon uses 8px.
- **Background:** No content cards. The entire splash stays on the checkpoint canvas.
- **Shadow Strategy:** None inside the window.
- **Border:** One-pixel structural separators only.
- **Internal Padding:** A 28px outer frame, 20px section rhythm, and 10–12px compact gaps.

### Launch Progress Rail

The rail has exactly three stages: Checks, Launching protected mode, and Protected session. Completed stages use a check, the active stage uses a dot and heavier ring, pending stages use a quiet ring, and failures use an exclamation mark. “Protected session” is complete only after authoritative admission and signed-bundle/build verification.

### Signed Game Hero

The hero is a locally verified PNG whose path and digest are bound into signed publisher claims. It is center-cropped to the approved wide composition. It is decorative and disappears on failures or when 200% scaling leaves insufficient space.

## 6. Do's and Don'ts

### Do:

- **Do** keep game identity, current milestone, and authority boundary visible in one scan.
- **Do** use only signed, digest-verified local PNG assets for publisher branding.
- **Do** preserve the full cinematic hero at normal desktop and minimum-window layouts.
- **Do** remove decorative artwork before allowing text to clip at large OS text scales.
- **Do** require a signed registration before showing repair or offline-play recovery actions.

### Don't:

- **Don't** use neon security theater, alarm-heavy red dashboards, or unexplained risk graphics.
- **Don't** show fake percentages, simulated progress, or a premature “Protected” claim.
- **Don't** use glassmorphism, generic card grids, or marketing-page composition.
- **Don't** let remote URLs, unsigned assets, animation, or tracking content enter publisher branding.
- **Don't** communicate success, failure, or progress by color alone.
- **Don't** keep the hero visible when it competes with recovery or 200% text reflow.
