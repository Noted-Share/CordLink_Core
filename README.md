# PJ_DM_Core

A DLL that adds Minecraft-based 3D spatial audio to Discord voice chat.

## Overview

Hooks Discord's voice engine to intercept per-user PCM audio, receives player coordinates from a Minecraft mod via shared memory (SHM), and renders 3D spatial audio in real-time using OpenAL.

## How It Works

```
Discord Voice Engine ──(hook)──> PCM Capture ──> SPSC Ring Buffer
                                                        │
Minecraft Mod ──(SHM)──> Player Coordinates             │
                              │                          │
                              └──> OpenAL 3D Spatial Audio <──┘
                                           │
                                   Distance-based volume + direction
```

1. **Discord Hooking** — Inline hooks on `GetAudioFrame` and `ConnectUser` to capture per-SSRC audio streams
2. **Shared Memory** — Minecraft Fabric mod writes listener/source coordinates to SHM; DLL reads safely via seqlock
3. **OpenAL Rendering** — Per-user AL sources with `AL_INVERSE_DISTANCE_CLAMPED` attenuation model
4. **Discord-MC Linking** — HTTP API maps Discord IDs to Minecraft usernames

## Key Technical Features

- **Lock-free SPSC ring buffer** — `std::atomic`-based, zero-lock audio transfer between hook and playback threads
- **Seqlock SHM reads** — Prevents torn reads across process boundaries
- **CAS-guarded shutdown** — `compare_exchange_strong` prevents concurrent teardown races
- **Adaptive sleep** — 1ms polling when audio is active, 5ms when idle

## Build

### Requirements
- Visual Studio 2022
- Windows SDK
- OpenAL Soft (`OpenAL32.dll` included)

### Build Command
```bash
MSBuild PJ_DM_Core.sln -p:Configuration=Release -p:Platform=x64
```

Output: `x64/Release/PJ_DM_Core.dll`

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `AUDIO_SAMPLE_RATE` | 48000 | Audio sample rate (Hz) |
| `REF_DISTANCE` | 3.0 | Full-volume radius (blocks) |
| `MAX_DISTANCE` | 24.0 | Max audible distance (blocks) |
| `ROLLOFF_FACTOR` | 1.0 | Distance attenuation factor |
| `HEARTBEAT_TIMEOUT` | 10000 | MC inactivity detection (ms) |

## Components

| Component | Role |
|-----------|------|
| **UserAudioManager** | OpenAL init, per-user audio source management, playback thread |
| **SHM Protocol** | Coordinate exchange with Minecraft mod (4096-byte shared memory) |
| **Hook Engine** | Inline patching of Discord functions + trampoline |
| **UDP Receiver** | External control commands (ping, unload) |
| **Discord Link API** | HTTP lookup for Discord ID to MC username mapping |

