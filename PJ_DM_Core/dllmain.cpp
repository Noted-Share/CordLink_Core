// PJ_DM_Core - Discord Voice Hook + Spatial Audio via Shared Memory
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <timeapi.h>
#include <Psapi.h>
#include <al.h>
#include <alc.h>
#include <alext.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include <mutex>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <winhttp.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "winhttp.lib")
#include "PJ_DM_Core.h"

//------------------------------------------
// Config
//------------------------------------------
#define DEBUG_LOG_ENABLED 0

namespace Config {
    constexpr int AUDIO_SAMPLE_RATE   = 48000;
    constexpr size_t RING_BUFFER_SIZE = 48000;   // 1 second
    constexpr size_t PLAYBACK_CHUNK   = 960;     // 20ms
    constexpr int MAX_QUEUED_BUFFERS  = 8;
    // Minecraft: 1 block = 1 meter
    constexpr float REF_DISTANCE      = 3.0f;   // full volume within 3 blocks
    constexpr float MAX_DISTANCE      = 24.0f;   // silent beyond 24 blocks
    constexpr float ROLLOFF_FACTOR    = 1.0f;    // natural inverse falloff
    constexpr float FADE_START        = 18.0f;   // smooth fade last 6 blocks
    constexpr DWORD INACTIVE_TIMEOUT  = 30000;   // 30s
    constexpr DWORD HEARTBEAT_TIMEOUT = 10000;   // 10s - auto-unload if MC stops updating
    constexpr int SHM_SIZE            = 4096;
    constexpr int SOURCE_ENTRY_SIZE   = 45;
    constexpr int MASTER_VOLUME_OFFSET = 2036;  // float, outside seqlock
    constexpr int LIVE_ROTATION_OFFSET = 2040;  // live yaw/pitch outside seqlock
    constexpr int REQUEST_OFFSET      = 2048;  // DLL -> mod: requested player names
    constexpr int REQUEST_NAME_SIZE   = 17;    // 1 byte len + 16 bytes name
    constexpr int MAX_SOURCES         = (REQUEST_OFFSET - 25) / SOURCE_ENTRY_SIZE;  // must not overlap request area
}


//------------------------------------------
// Hook types & originals
//------------------------------------------
using ConnectUserFunc   = void(__fastcall*)(void*, void*, int, void*, bool);
using GetAudioFrameFunc = int(__fastcall*)(void*, int, void*);

ConnectUserFunc   Original_ConnectUser   = nullptr;
GetAudioFrameFunc Original_GetAudioFrame = nullptr;

//------------------------------------------
// Globals
//------------------------------------------
HMODULE g_hModule = nullptr;
static std::atomic<bool> g_shutdownFlag{ false };
static std::atomic<uint64_t> g_hookProcessCount{ 0 };  // counts ProcessAudioData calls

namespace FrameOff {
    constexpr int samples_per_channel = 0x18;
    constexpr int sample_rate_hz      = 0x20;
    constexpr int num_channels        = 0x28;
    constexpr int data_array          = 0x50;
}
constexpr int REMOTE_SSRC_OFFSET = 0xF8;

//------------------------------------------
// Debug log
//------------------------------------------
static std::mutex g_consoleMutex;
void DebugLog(const char* format, ...) {
#if DEBUG_LOG_ENABLED
    std::lock_guard<std::mutex> lock(g_consoleMutex);
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
#endif
}

//------------------------------------------
// Pattern scanning
//------------------------------------------
static uintptr_t FindStringRef(HMODULE hModule, const char* searchStr)
{
    MODULEINFO modInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
    uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)modInfo.SizeOfImage;
    size_t strLen = strlen(searchStr);

    uintptr_t strAddr = 0;
    for (uintptr_t i = base; i < base + size - strLen; i++) {
        if (memcmp((void*)i, searchStr, strLen) == 0) {
            strAddr = i;
            break;
        }
    }
    if (!strAddr) return 0;

    for (uintptr_t i = base; i < base + size - 7; i++) {
        BYTE* p = (BYTE*)i;
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D) {
            if ((p[2] & 0xC7) == 0x05) {
                int32_t disp = *(int32_t*)(p + 3);
                if (i + 7 + disp == strAddr) {
                    uintptr_t scanLimit = (i > base + 0x1000) ? (i - 0x1000) : base;
                    for (uintptr_t fn = i; fn > scanLimit; fn--) {
                        BYTE* f = (BYTE*)fn;
                        if (f[0] == 0x41 && f[1] == 0x57 && f[2] == 0x41 && f[3] == 0x56 &&
                            f[4] == 0x41 && f[5] == 0x55 && f[6] == 0x41 && f[7] == 0x54) {
                            return fn;
                        }
                    }
                }
            }
        }
    }
    return 0;
}


//------------------------------------------
// Inline hook engine (generic, supports multiple hooks)
//------------------------------------------
struct InlineHook {
    uintptr_t address = 0;
    BYTE      originalBytes[16] = { 0 };
    void*     trampoline = nullptr;
};

static constexpr SIZE_T PATCH_SIZE = 12;

static bool InstallInlineHook(void* target, void* hook, void** outOriginal, InlineHook& state)
{
    if (!target || !hook || !outOriginal) return false;

    DWORD oldProtect;
    if (!VirtualProtect(target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(state.originalBytes, target, PATCH_SIZE);
    state.address = (uintptr_t)target;

    state.trampoline = VirtualAlloc(nullptr, PATCH_SIZE + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!state.trampoline) {
        VirtualProtect(target, PATCH_SIZE, oldProtect, &oldProtect);
        return false;
    }

    // Copy original bytes to trampoline, then jump back
    memcpy(state.trampoline, target, PATCH_SIZE);
    BYTE* p = (BYTE*)state.trampoline + PATCH_SIZE;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)(p + 2) = (uint64_t)target + PATCH_SIZE;
    p[10] = 0xFF; p[11] = 0xE0;

    // Patch target to jump to hook
    BYTE patch[16] = { 0 };
    patch[0] = 0x48; patch[1] = 0xB8;
    *(uint64_t*)(patch + 2) = (uint64_t)hook;
    patch[10] = 0xFF; patch[11] = 0xE0;
    memcpy(target, patch, PATCH_SIZE);

    FlushInstructionCache(GetCurrentProcess(), target, PATCH_SIZE);
    VirtualProtect(target, PATCH_SIZE, oldProtect, &oldProtect);
    *outOriginal = state.trampoline;
    return true;
}

static void RemoveInlineHook(InlineHook& state)
{
    if (!state.address) return;
    DWORD oldProtect;
    VirtualProtect((void*)state.address, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)state.address, state.originalBytes, PATCH_SIZE);
    FlushInstructionCache(GetCurrentProcess(), (void*)state.address, PATCH_SIZE);
    VirtualProtect((void*)state.address, PATCH_SIZE, oldProtect, &oldProtect);
    if (state.trampoline) VirtualFree(state.trampoline, 0, MEM_RELEASE);
    state = {};
}

static InlineHook g_hookGetAudioFrame;
static InlineHook g_hookConnectUser;

// Forward declarations
static void CleanupHooks();
void StopUdpReceiver();
#if DEBUG_LOG_ENABLED
static void StopConsoleThread();
#endif

//------------------------------------------
// API: discord_id -> MC name resolution
//------------------------------------------
static std::mutex g_linkMutex;
static std::map<std::string, std::string> g_discordToMcName;
static std::set<std::string> g_linkResolvePending;
static std::map<std::string, ULONGLONG> g_linkResolveRetryAt;
static constexpr ULONGLONG LINK_RESOLVE_RETRY_MS = 5000;

static std::string HttpGet(const wchar_t* host, INTERNET_PORT port, bool secure, const wchar_t* path) {
    std::string result;
    HINTERNET hSession = WinHttpOpen(L"CordlinkDLL/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                              WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           NULL, &statusCode, &statusSize, NULL);
        if (statusCode == 200) {
            char buf[4096];
            DWORD bytesRead;
            while (WinHttpReadData(hRequest, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
                buf[bytesRead] = '\0';
                result += buf;
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

static std::string StripDashes(const std::string& uuid) {
    std::string out;
    for (char c : uuid) { if (c != '-') out += c; }
    return out;
}

static bool BeginDiscordLinkResolve(const std::string& discordId) {
    ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_linkMutex);
    if (g_discordToMcName.find(discordId) != g_discordToMcName.end()) return false;
    if (g_linkResolvePending.find(discordId) != g_linkResolvePending.end()) return false;
    auto retryIt = g_linkResolveRetryAt.find(discordId);
    if (retryIt != g_linkResolveRetryAt.end() && now < retryIt->second) return false;
    g_linkResolveRetryAt.erase(discordId);
    g_linkResolvePending.insert(discordId);
    return true;
}

static void ResolveDiscordLink(const std::string& discordId) {
    std::wstring path(L"/api/link/");
    path.append(discordId.begin(), discordId.end());
    std::string response = HttpGet(L"slcdn.info", 8080, false, path.c_str());
    std::string resolvedName;

    if (!response.empty()) {
        // Parse "name":"..." from JSON
        size_t pos = response.find("\"name\":\"");
        if (pos != std::string::npos) {
            pos += 8;
            size_t end = response.find("\"", pos);
            if (end != std::string::npos) {
                resolvedName = response.substr(pos, end - pos);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_linkMutex);
        g_linkResolvePending.erase(discordId);
        if (!resolvedName.empty()) {
            g_discordToMcName[discordId] = resolvedName;
            g_linkResolveRetryAt.erase(discordId);
            DebugLog("[API] Resolved %s -> %s", discordId.c_str(), resolvedName.c_str());
        }
        else {
            g_linkResolveRetryAt[discordId] = GetTickCount64() + LINK_RESOLVE_RETRY_MS;
            DebugLog("[API] Resolve failed for %s; retry after cooldown", discordId.c_str());
        }
    }
}

static void QueueDiscordLinkResolve(const std::string& discordId) {
    if (!BeginDiscordLinkResolve(discordId)) return;
    auto* idCopy = new std::string(discordId);
    HANDLE h = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        std::string* id = (std::string*)param;
        ResolveDiscordLink(*id);
        delete id;
        return 0;
    }, idCopy, 0, nullptr);
    if (h) {
        CloseHandle(h);
    } else {
        // Thread creation failed: clean up pending state so future retries work
        delete idCopy;
        std::lock_guard<std::mutex> lock(g_linkMutex);
        g_linkResolvePending.erase(discordId);
        g_linkResolveRetryAt[discordId] = GetTickCount64() + LINK_RESOLVE_RETRY_MS;
    }
}

static void SilenceAudioFrame(void* audio_frame) {
    if (!audio_frame) return;
    char* frame = (char*)audio_frame;
    size_t samples  = *(size_t*)(frame + FrameOff::samples_per_channel);
    size_t channels = *(size_t*)(frame + FrameOff::num_channels);
    int16_t* pcm    = (int16_t*)(frame + FrameOff::data_array);
    if (pcm && samples > 0 && samples <= 7680 && channels > 0 && channels <= 2) {
        memset(pcm, 0, samples * channels * sizeof(int16_t));
    }
}

//------------------------------------------
// Audio Manager
//------------------------------------------
class UserAudioManager {
public:
    struct UserAudioData {
        ALuint source = 0;
        ULONGLONG lastWriteTime = 0;
        bool positioned = false;
        int16_t* ringBuffer = nullptr;
        std::atomic<uint64_t> writePos{ 0 };
        std::atomic<uint64_t> readPos{ 0 };

        UserAudioData() {
            ringBuffer = new int16_t[Config::RING_BUFFER_SIZE]();
        }
        ~UserAudioData() {
            delete[] ringBuffer;
        }
        UserAudioData(const UserAudioData&) = delete;
        UserAudioData& operator=(const UserAudioData&) = delete;
        UserAudioData(UserAudioData&& o) noexcept
            : source(o.source), lastWriteTime(o.lastWriteTime),
              positioned(o.positioned),
              ringBuffer(o.ringBuffer) {
            writePos.store(o.writePos.load(std::memory_order_relaxed), std::memory_order_relaxed);
            readPos.store(o.readPos.load(std::memory_order_relaxed), std::memory_order_relaxed);
            o.ringBuffer = nullptr;
        }
        UserAudioData& operator=(UserAudioData&& o) noexcept {
            if (this != &o) {
                delete[] ringBuffer;
                source = o.source; lastWriteTime = o.lastWriteTime;
                positioned = o.positioned;
                ringBuffer = o.ringBuffer;
                writePos.store(o.writePos.load(std::memory_order_relaxed), std::memory_order_relaxed);
                readPos.store(o.readPos.load(std::memory_order_relaxed), std::memory_order_relaxed);
                o.ringBuffer = nullptr;
            }
            return *this;
        }

        // SPSC lock-free: Write (producer/hook thread), Read (consumer/playback thread)
        void Write(const int16_t* data, size_t count) {
            uint64_t wp = writePos.load(std::memory_order_relaxed);
            for (size_t i = 0; i < count; i++) {
                ringBuffer[wp % Config::RING_BUFFER_SIZE] = data[i];
                wp++;
            }
            writePos.store(wp, std::memory_order_release);
        }
        uint64_t Available() const {
            return writePos.load(std::memory_order_acquire) - readPos.load(std::memory_order_acquire);
        }

        size_t Read(int16_t* out, size_t count) {
            uint64_t wp = writePos.load(std::memory_order_acquire);
            uint64_t rp = readPos.load(std::memory_order_relaxed);
            uint64_t avail = wp - rp;
            // Overflow: writer lapped reader — skip to latest data
            if (avail > Config::RING_BUFFER_SIZE) {
                rp = wp - Config::RING_BUFFER_SIZE;
                avail = Config::RING_BUFFER_SIZE;
            }
            size_t toRead = (count < avail) ? count : (size_t)avail;
            for (size_t i = 0; i < toRead; i++) {
                out[i] = ringBuffer[rp % Config::RING_BUFFER_SIZE];
                rp++;
            }
            readPos.store(rp, std::memory_order_release);
            for (size_t i = toRead; i < count; i++) out[i] = 0;
            return toRead;
        }
    };

    std::unordered_map<uint32_t, std::string> ssrcToUserId;
    std::unordered_map<uint32_t, UserAudioData> userAudioMap;
    std::mutex dataMutex;
    std::atomic<bool> initialized{ false };
    std::atomic<bool> running{ false };
    HANDLE playbackThread = nullptr;

    ALCdevice* device = nullptr;
    ALCcontext* context = nullptr;

    // Shared memory (managed by PlaybackThread)
    HANDLE shmHandle = nullptr;
    uint8_t* shmView = nullptr;
    uint32_t shmLastSeq = 0;

    bool Initialize() {
        std::lock_guard<std::mutex> lock(dataMutex);
        if (initialized) return true;

        device = alcOpenDevice(nullptr);
        if (!device) return false;

        ALCint attrs[] = {
            ALC_FREQUENCY, Config::AUDIO_SAMPLE_RATE,
            ALC_HRTF_SOFT, ALC_TRUE,
            0
        };
        context = alcCreateContext(device, attrs);
        if (!context) { alcCloseDevice(device); return false; }

        alcMakeContextCurrent(context);
        alListener3f(AL_POSITION, 0.0f, 0.0f, 0.0f);
        ALfloat ori[] = { 0.0f, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f };
        alListenerfv(AL_ORIENTATION, ori);
        alDistanceModel(AL_INVERSE_DISTANCE_CLAMPED);
        alDopplerFactor(0.0f);  // disable Doppler - discrete position jumps cause pitch artifacts
        initialized = true;

        ALCint hrtfState = 0;
        alcGetIntegerv(device, ALC_HRTF_SOFT, 1, &hrtfState);
        DebugLog("OpenAL initialized (HRTF: %s)", hrtfState ? "ON" : "OFF");
        return true;
    }

    void StartPlayback() {
        running = true;
        playbackThread = CreateThread(nullptr, 0, PlaybackThreadFunc, this, 0, nullptr);
    }

    void CleanupAllSources() {
        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto& pair : userAudioMap) {
            auto& ud = pair.second;
            if (ud.source != 0) {
                alSourceStop(ud.source);
                ALint p = 0;
                alGetSourcei(ud.source, AL_BUFFERS_PROCESSED, &p);
                while (p-- > 0) {
                    ALuint buf;
                    alSourceUnqueueBuffers(ud.source, 1, &buf);
                    alDeleteBuffers(1, &buf);
                }
                alDeleteSources(1, &ud.source);
                ud.source = 0;
            }
        }
        userAudioMap.clear();
    }

    void DestroyAudio() {
        CleanupAllSources();
        if (context) {
            alcMakeContextCurrent(nullptr);
            alcDestroyContext(context);
            context = nullptr;
        }
        if (device) {
            alcCloseDevice(device);
            device = nullptr;
        }
    }

    void ProcessAudioData(uint32_t ssrc, const int16_t* pcm, size_t samples, int channels) {
        std::lock_guard<std::mutex> lock(dataMutex);
        auto it = userAudioMap.find(ssrc);
        if (it == userAudioMap.end()) {
            it = userAudioMap.emplace(ssrc, UserAudioData()).first;
            DebugLog("Queued new user for AL source creation: SSRC=%u", (unsigned)ssrc);
        }
        // Convert stereo to mono if needed (stack buffer, no heap alloc)
        int16_t mono[7680];
        size_t monoSamples = (samples <= 7680) ? samples : 7680;
        for (size_t i = 0; i < monoSamples; i++) {
            mono[i] = (channels == 2) ? pcm[i * 2] : pcm[i];
        }
        it->second.Write(mono, monoSamples);
        it->second.lastWriteTime = GetTickCount64();
    }

private:
    static void UpdatePositionsFromShm(UserAudioManager* mgr) {
        // Try to open shared memory if not mapped
        if (!mgr->shmView) {
            mgr->shmHandle = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, "CordlinkPositionData");
            if (mgr->shmHandle) {
                mgr->shmView = (uint8_t*)MapViewOfFile(mgr->shmHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, Config::SHM_SIZE);
                if (mgr->shmView) {
                    DebugLog("[SHM] Shared memory opened successfully");
                } else {
                    DebugLog("[SHM] MapViewOfFile failed");
                    CloseHandle(mgr->shmHandle);
                    mgr->shmHandle = nullptr;
                }
            }
        }
        if (!mgr->shmView) return;

        // Always apply live rotation (outside seqlock, updated at ~500Hz)
        {
            float liveYaw, livePitch;
            memcpy(&liveYaw,   mgr->shmView + Config::LIVE_ROTATION_OFFSET, 4);
            memcpy(&livePitch, mgr->shmView + Config::LIVE_ROTATION_OFFSET + 4, 4);
            float fx = -sinf(liveYaw) * cosf(livePitch);
            float fy = -sinf(livePitch);
            float fz = cosf(liveYaw) * cosf(livePitch);
            ALfloat orientation[] = { fx, fy, fz, 0.0f, 1.0f, 0.0f };
            alListenerfv(AL_ORIENTATION, orientation);
        }

        // Master volume from SHM (outside seqlock)
        {
            float vol;
            memcpy(&vol, mgr->shmView + Config::MASTER_VOLUME_OFFSET, 4);
            if (vol >= 0.0f && vol <= 2.0f) {
                alListenerf(AL_GAIN, vol);
            }
        }

        // Seqlock: read seq, read data, re-read seq — discard if changed (torn read)
        uint32_t seq;
        memcpy(&seq, mgr->shmView, 4);
        if (seq == mgr->shmLastSeq) return;

        // Listener position (rotation read from live area above)
        float lx, ly, lz;
        memcpy(&lx, mgr->shmView + 4,  4);
        memcpy(&ly, mgr->shmView + 8,  4);
        memcpy(&lz, mgr->shmView + 12, 4);

        // Phase 1: Read all source entries from SHM into local storage (stack, no heap)
        uint8_t numSources = mgr->shmView[24];
        if (numSources > Config::MAX_SOURCES) numSources = Config::MAX_SOURCES;
        struct ShmSourceEntry { char mcName[33]; uint8_t nameLen; float x, y, z; };
        ShmSourceEntry shmSources[Config::MAX_SOURCES];
        int offset = 25;
        for (uint8_t i = 0; i < numSources; i++) {
            uint8_t idLen = mgr->shmView[offset];
            if (idLen > 32) idLen = 32;
            memcpy(shmSources[i].mcName, mgr->shmView + offset + 1, idLen);
            shmSources[i].mcName[idLen] = '\0';
            shmSources[i].nameLen = idLen;
            memcpy(&shmSources[i].x, mgr->shmView + offset + 33, 4);
            memcpy(&shmSources[i].y, mgr->shmView + offset + 37, 4);
            memcpy(&shmSources[i].z, mgr->shmView + offset + 41, 4);
            offset += Config::SOURCE_ENTRY_SIZE;
        }

        // Seqlock verify: re-read seq after all SHM reads; discard if writer was mid-update
        uint32_t seq2;
        memcpy(&seq2, mgr->shmView, 4);
        if (seq2 != seq) return;  // torn read, skip this tick
        mgr->shmLastSeq = seq;

        // Phase 2: Apply listener position (rotation already applied above from live area)
        alListener3f(AL_POSITION, lx, ly, lz);

        std::vector<uint32_t> positionedUsers;

        // Build mcName -> ssrc lookup from current link data
        std::unordered_map<std::string, uint32_t> mcNameToSsrc;
        {
            std::lock_guard<std::mutex> linkLock(g_linkMutex);
            std::lock_guard<std::mutex> dataLock(mgr->dataMutex);
            for (auto& kv : mgr->ssrcToUserId) {
                auto linkIt = g_discordToMcName.find(kv.second);
                if (linkIt != g_discordToMcName.end()) {
                    mcNameToSsrc[linkIt->second] = kv.first;
                }
            }
        }

        // Write requested player names to SHM (DLL -> mod)
        {
            uint8_t count = 0;
            int woff = Config::REQUEST_OFFSET + 1;
            for (auto& kv : mcNameToSsrc) {
                uint8_t nameLen = (uint8_t)(kv.first.size() < 16 ? kv.first.size() : 16);
                if (woff + Config::REQUEST_NAME_SIZE > Config::SHM_SIZE) break;
                mgr->shmView[woff] = nameLen;
                memcpy(mgr->shmView + woff + 1, kv.first.c_str(), nameLen);
                memset(mgr->shmView + woff + 1 + nameLen, 0, 16 - nameLen);
                woff += Config::REQUEST_NAME_SIZE;
                count++;
            }
            mgr->shmView[Config::REQUEST_OFFSET] = count;
        }

        static ULONGLONG lastShmDebugTime = 0;
        ULONGLONG nowDbg = GetTickCount64();
        bool shmDebugLog = (nowDbg - lastShmDebugTime > 5000);
        if (shmDebugLog) {
            lastShmDebugTime = nowDbg;
            DebugLog("[SHM] numSources=%d, linkMap entries=%d", numSources, (int)mcNameToSsrc.size());
            for (auto& kv : mcNameToSsrc)
                DebugLog("[SHM]   link: %s -> SSRC=%u", kv.first.c_str(), (unsigned)kv.second);
        }

        // Phase 3: Apply source positions from local data
        for (uint8_t i = 0; i < numSources; i++) {
            auto& entry = shmSources[i];
            std::string mcName(entry.mcName, entry.nameLen);
            if (shmDebugLog)
                DebugLog("[SHM] src[%d]: name=%s pos=(%.1f,%.1f,%.1f)", i, entry.mcName, entry.x, entry.y, entry.z);

            // Match MC name to audio source via SSRC
            {
                auto mapIt = mcNameToSsrc.find(mcName);
                if (mapIt != mcNameToSsrc.end()) {
                    std::lock_guard<std::mutex> lock(mgr->dataMutex);
                    auto it = mgr->userAudioMap.find(mapIt->second);
                    if (it != mgr->userAudioMap.end() && it->second.source != 0) {
                        ALuint source = it->second.source;
                        positionedUsers.push_back(mapIt->second);
                        alSource3f(source, AL_POSITION, entry.x, entry.y, entry.z);
                        float dx = entry.x - lx, dy = entry.y - ly, dz = entry.z - lz;
                        float dist = sqrtf(dx*dx + dy*dy + dz*dz);
                        float gain = 1.0f;
                        if (dist >= Config::MAX_DISTANCE) gain = 0.0f;
                        else if (dist > Config::FADE_START) {
                            float t = (dist - Config::FADE_START) / (Config::MAX_DISTANCE - Config::FADE_START);
                            gain = 1.0f - t * t;  // quadratic ease-out
                        }
                        alSourcef(source, AL_GAIN, gain);
                        if (shmDebugLog) {
                            float dx = entry.x - lx, dy = entry.y - ly, dz = entry.z - lz;
                            float dist = sqrtf(dx*dx + dy*dy + dz*dz);
                            ALint state;
                            alGetSourcei(source, AL_SOURCE_STATE, &state);
                            ALint queued = 0;
                            alGetSourcei(source, AL_BUFFERS_QUEUED, &queued);
                            DebugLog("[SHM]   MATCHED SSRC=%u dist=%.1f state=%s queued=%d",
                                (unsigned)mapIt->second, dist,
                                state == AL_PLAYING ? "PLAYING" : state == AL_STOPPED ? "STOPPED" : "OTHER",
                                queued);
                        }
                    }
                } else if (shmDebugLog) {
                    DebugLog("[SHM]   NO MATCH for name=%s", entry.mcName);
                }
            }
        }

        // Unmatched sources: move far away so distance model silences them naturally
        {
            std::lock_guard<std::mutex> lock(mgr->dataMutex);
            for (auto& pair : mgr->userAudioMap) {
                uint32_t ssrc = pair.first;
                auto& ud = pair.second;
                bool mapped = false;
                for (auto& id : positionedUsers) {
                    if (id == ssrc) { mapped = true; break; }
                }
                ud.positioned = mapped;
                if (!mapped && ud.source != 0) {
                    alSourcef(ud.source, AL_GAIN, 0.0f);
                }
            }
        }
    }

    static bool ManageAudioBuffers(UserAudioManager* mgr, int16_t* chunk) {
        std::lock_guard<std::mutex> lock(mgr->dataMutex);
        bool hasActiveAudio = false;

        static ULONGLONG lastBufLog = 0;
        ULONGLONG nowBuf = GetTickCount64();
        bool bufLog = (nowBuf - lastBufLog > 5000);
        if (bufLog) {
            lastBufLog = nowBuf;
            uint64_t pc = g_hookProcessCount.load(std::memory_order_relaxed);
            DebugLog("[Audio] hookProcessCount=%llu", (unsigned long long)pc);
            for (auto& pair : mgr->userAudioMap) {
                auto& ud = pair.second;
                ALint q = 0, st = 0;
                if (ud.source) { alGetSourcei(ud.source, AL_BUFFERS_QUEUED, &q); alGetSourcei(ud.source, AL_SOURCE_STATE, &st); }
                DebugLog("[Audio] SSRC=%u ringAvail=%llu queued=%d state=%d positioned=%d",
                    (unsigned)pair.first, (unsigned long long)ud.Available(), q, st, ud.positioned ? 1 : 0);
            }
        }

        for (auto& pair : mgr->userAudioMap) { uint32_t ssrc = pair.first; auto& ud = pair.second;
            // Lazy-init AL source on playback thread (thread-safe for OpenAL)
            if (ud.source == 0) {
                alGenSources(1, &ud.source);
                alSourcef(ud.source, AL_REFERENCE_DISTANCE, Config::REF_DISTANCE);
                alSourcef(ud.source, AL_MAX_DISTANCE, Config::MAX_DISTANCE);
                alSourcef(ud.source, AL_ROLLOFF_FACTOR, Config::ROLLOFF_FACTOR);
                alSourcei(ud.source, AL_SOURCE_RELATIVE, AL_FALSE);
                DebugLog("Created OpenAL source for SSRC=%u on playback thread", (unsigned)ssrc);
            }

            // Unqueue processed buffers
            ALint processed = 0;
            alGetSourcei(ud.source, AL_BUFFERS_PROCESSED, &processed);
            while (processed-- > 0) {
                ALuint buf;
                alSourceUnqueueBuffers(ud.source, 1, &buf);
                alDeleteBuffers(1, &buf);
            }

            // Always fill up to MAX_QUEUED_BUFFERS (silence if no data)
            // This prevents sources from ever reaching STOPPED state
            ALint queued = 0;
            alGetSourcei(ud.source, AL_BUFFERS_QUEUED, &queued);
            while (queued < Config::MAX_QUEUED_BUFFERS) {
                uint64_t avail = ud.Available();
                if (avail >= Config::PLAYBACK_CHUNK) {
                    ud.Read(chunk, Config::PLAYBACK_CHUNK);
                    hasActiveAudio = true;
                } else {
                    memset(chunk, 0, Config::PLAYBACK_CHUNK * sizeof(int16_t));
                }
                ALuint buffer;
                alGenBuffers(1, &buffer);
                alBufferData(buffer, AL_FORMAT_MONO16, chunk,
                    (ALsizei)(Config::PLAYBACK_CHUNK * sizeof(int16_t)), Config::AUDIO_SAMPLE_RATE);
                alSourceQueueBuffers(ud.source, 1, &buffer);
                queued++;
            }

            // Start playing when enough buffered data
            ALint state;
            alGetSourcei(ud.source, AL_SOURCE_STATE, &state);
            if (state != AL_PLAYING) {
                alGetSourcei(ud.source, AL_BUFFERS_QUEUED, &queued);
                if (queued >= 2) alSourcePlay(ud.source);
            }
        }

        // Cleanup inactive users
        ULONGLONG now = GetTickCount64();
        std::vector<uint32_t> toRemove;
        for (auto& pair : mgr->userAudioMap) { uint32_t ssrc = pair.first; auto& ud = pair.second;
            if (ud.lastWriteTime > 0 && now - ud.lastWriteTime > Config::INACTIVE_TIMEOUT) {
                if (ud.source != 0) {
                    alSourceStop(ud.source);
                    ALint p = 0;
                    alGetSourcei(ud.source, AL_BUFFERS_PROCESSED, &p);
                    while (p-- > 0) {
                        ALuint buf;
                        alSourceUnqueueBuffers(ud.source, 1, &buf);
                        alDeleteBuffers(1, &buf);
                    }
                    alDeleteSources(1, &ud.source);
                }
                toRemove.push_back(ssrc);
            }
        }
        for (uint32_t id : toRemove) {
            mgr->userAudioMap.erase(id);
            DebugLog("[Cleanup] Removed inactive SSRC=%u", (unsigned)id);
        }
        return hasActiveAudio;
    }

    static DWORD WINAPI PlaybackThreadFunc(LPVOID param) {
        auto* mgr = (UserAudioManager*)param;
        int16_t chunk[Config::PLAYBACK_CHUNK];

        alcMakeContextCurrent(mgr->context);
        timeBeginPeriod(1);

        uint32_t lastSeenSeq = 0;
        ULONGLONG lastSeqChangeTime = GetTickCount64();

        while (mgr->running) {
            UpdatePositionsFromShm(mgr);
            bool hasActiveAudio = ManageAudioBuffers(mgr, chunk);

            // Heartbeat: detect if Minecraft stopped updating shared memory
            if (mgr->shmView) {
                if (mgr->shmLastSeq != lastSeenSeq) {
                    lastSeenSeq = mgr->shmLastSeq;
                    lastSeqChangeTime = GetTickCount64();
                } else if (GetTickCount64() - lastSeqChangeTime > Config::HEARTBEAT_TIMEOUT) {
                    DebugLog("Heartbeat timeout - Minecraft likely closed, auto-unloading");
                    break;  // exit playback loop, triggers unload
                }
            }

            // Adaptive sleep: 1ms when audio active, 5ms when idle
            Sleep(hasActiveAudio ? 1 : 5);
        }

        timeEndPeriod(1);
        if (mgr->shmView)   { UnmapViewOfFile(mgr->shmView); mgr->shmView = nullptr; }
        if (mgr->shmHandle)  { CloseHandle(mgr->shmHandle); mgr->shmHandle = nullptr; }

        // If we exited due to heartbeat timeout (not normal shutdown), do cleanup on this thread
        bool expected = false;
        if (g_shutdownFlag.compare_exchange_strong(expected, true)) {
            Sleep(200);  // let in-flight hook calls finish
#if DEBUG_LOG_ENABLED
            StopConsoleThread();
#endif
            CleanupHooks();
            mgr->DestroyAudio();
            StopUdpReceiver();
#if DEBUG_LOG_ENABLED
            HWND hConsole = GetConsoleWindow();
            FreeConsole();
            if (hConsole) PostMessage(hConsole, WM_CLOSE, 0, 0);
#endif
            FreeLibraryAndExitThread(g_hModule, 0);
        }

        return 0;
    }
};

UserAudioManager g_audioManager;

//------------------------------------------
// Hooked functions
//------------------------------------------
void __fastcall Hooked_ConnectUser(void* thisptr, void* userIdStr, int audioSsrc, void* ssrcArray, bool flag) {
    if (g_shutdownFlag) { Original_ConnectUser(thisptr, userIdStr, audioSsrc, ssrcArray, flag); return; }
    std::string userId;
    if (userIdStr && audioSsrc != 0) {
        size_t len = *(size_t*)((char*)userIdStr + 0x10);
        size_t cap = *(size_t*)((char*)userIdStr + 0x18);
        char* str = (cap >= 0x10) ? *(char**)userIdStr : (char*)userIdStr;
        userId.assign(str, len);
    }

    Original_ConnectUser(thisptr, userIdStr, audioSsrc, ssrcArray, flag);

    if (!userId.empty()) {
        {
            std::lock_guard<std::mutex> lock(g_audioManager.dataMutex);
            // Remove old SSRC for same userId (SSRC reassignment)
            uint32_t oldSsrc = 0;
            for (auto& kv : g_audioManager.ssrcToUserId) {
                if (kv.second == userId && kv.first != (uint32_t)audioSsrc) {
                    oldSsrc = kv.first;
                    break;
                }
            }
            if (oldSsrc != 0) {
                g_audioManager.ssrcToUserId.erase(oldSsrc);
                auto it = g_audioManager.userAudioMap.find(oldSsrc);
                if (it != g_audioManager.userAudioMap.end()) {
                    if (it->second.source != 0) {
                        alSourceStop(it->second.source);
                        ALint p = 0;
                        alGetSourcei(it->second.source, AL_BUFFERS_PROCESSED, &p);
                        while (p-- > 0) { ALuint buf; alSourceUnqueueBuffers(it->second.source, 1, &buf); alDeleteBuffers(1, &buf); }
                        alDeleteSources(1, &it->second.source);
                    }
                    g_audioManager.userAudioMap.erase(it);
                }
                DebugLog("[ConnectUser] Replaced old SSRC=%u for %s", (unsigned)oldSsrc, userId.c_str());
            }
            g_audioManager.ssrcToUserId[(uint32_t)audioSsrc] = userId;
        }
        DebugLog("[ConnectUser] SSRC=%d -> %s", audioSsrc, userId.c_str());
        QueueDiscordLinkResolve(userId);
    }
}

static int SafeCallOriginal(void* thisptr, int sample_rate_hz, void* audio_frame) {
    __try { return Original_GetAudioFrame(thisptr, sample_rate_hz, audio_frame); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

int __fastcall Hooked_GetAudioFrame(void* thisptr, int sample_rate_hz, void* audio_frame) {
    int ret = SafeCallOriginal(thisptr, sample_rate_hz, audio_frame);
    if (g_shutdownFlag || ret < 0 || !thisptr || !audio_frame) return ret;

    uint32_t ssrc = *(uint32_t*)((char*)thisptr + REMOTE_SSRC_OFFSET);
    std::string discordId;

    {
        std::lock_guard<std::mutex> dataLock(g_audioManager.dataMutex);
        auto it = g_audioManager.ssrcToUserId.find(ssrc);
        if (it != g_audioManager.ssrcToUserId.end()) discordId = it->second;
    }

    if (discordId.empty()) {
        static std::mutex unknownMtx;
        static std::set<uint32_t> loggedUnknown;
        {
            std::lock_guard<std::mutex> lock(unknownMtx);
            if (loggedUnknown.insert(ssrc).second)
                DebugLog("[Hook] Unknown SSRC=%u (no ConnectUser), silencing", (unsigned)ssrc);
        }
        SilenceAudioFrame(audio_frame);
        return ret;
    }

    bool linked = false;
    std::string mcName;
    {
        std::lock_guard<std::mutex> linkLock(g_linkMutex);
        auto it = g_discordToMcName.find(discordId);
        if (it != g_discordToMcName.end()) {
            linked = true;
            mcName = it->second;
        }
    }
    if (!linked) {
        SilenceAudioFrame(audio_frame);
        return ret;
    }

    // Keep user alive even if muted
    {
        std::lock_guard<std::mutex> lock(g_audioManager.dataMutex);
        auto it = g_audioManager.userAudioMap.find(ssrc);
        if (it != g_audioManager.userAudioMap.end())
            it->second.lastWriteTime = GetTickCount64();
    }

    char* frame = (char*)audio_frame;
    size_t samples  = *(size_t*)(frame + FrameOff::samples_per_channel);
    int sr          = *(int*)(frame + FrameOff::sample_rate_hz);
    size_t channels = *(size_t*)(frame + FrameOff::num_channels);
    int16_t* pcm    = (int16_t*)(frame + FrameOff::data_array);

    if (sr > 0 && sr <= 48000 && samples > 0 && samples <= 7680 && channels > 0 && channels <= 2) {
        g_audioManager.ProcessAudioData(ssrc, pcm, samples, (int)channels);
        g_hookProcessCount.fetch_add(1, std::memory_order_relaxed);
        memset(pcm, 0, samples * channels * sizeof(int16_t));
    }

    return ret;
}

//------------------------------------------
// Hook initialization / cleanup
//------------------------------------------
static bool InitializeHooks() {
    HMODULE hVoice = GetModuleHandleW(L"discord_voice.node");
    if (!hVoice) {
        DebugLog("discord_voice.node not found");
        return false;
    }

    // GetAudioFrame hook (required)
    uintptr_t addr = FindStringRef(hVoice, "ChannelReceive::GetAudioFrameWithInfo");
    if (!addr) { DebugLog("GetAudioFrame not found"); return false; }

    if (!InstallInlineHook((void*)addr, Hooked_GetAudioFrame, (void**)&Original_GetAudioFrame, g_hookGetAudioFrame)) {
        DebugLog("GetAudioFrame hook failed");
        return false;
    }
    DebugLog("GetAudioFrame hooked at %p", (void*)addr);

    // ConnectUser hook (optional)
    uintptr_t addr2 = FindStringRef(hVoice, "Ignoring ConnectUser call for existing user");
    if (addr2) {
        if (InstallInlineHook((void*)addr2, Hooked_ConnectUser, (void**)&Original_ConnectUser, g_hookConnectUser)) {
            DebugLog("ConnectUser hooked at %p", (void*)addr2);
        }
    }

    return true;
}

static void CleanupHooks() {
    RemoveInlineHook(g_hookGetAudioFrame);
    RemoveInlineHook(g_hookConnectUser);
}

//------------------------------------------
// UDP Command Receiver (text commands only: P=ping, Q=unload)
//------------------------------------------
static std::atomic<bool> g_udpRunning{ false };
static HANDLE g_udpThread = nullptr;
static SOCKET g_udpSocket = INVALID_SOCKET;

void StartUdpReceiver();
void StopUdpReceiver();

static void HandleUdpCommand(const char* data, int len, sockaddr_in* from) {
    if (len <= 0) return;

    if (data[0] == 'P') {
        const char* pong = "PONG\n";
        sendto(g_udpSocket, pong, (int)strlen(pong), 0, (sockaddr*)from, sizeof(*from));
    }
    else if (data[0] == 'L') {
        // Link command: L<discordId>:<mcName>
        std::string payload(data + 1, len - 1);
        size_t sep = payload.find(':');
        if (sep != std::string::npos && sep > 0 && sep < payload.size() - 1) {
            std::string discordId = payload.substr(0, sep);
            std::string mcName = payload.substr(sep + 1);
            {
                std::lock_guard<std::mutex> lock(g_linkMutex);
                g_discordToMcName[discordId] = mcName;
                g_linkResolvePending.erase(discordId);
                g_linkResolveRetryAt.erase(discordId);
            }
            DebugLog("[CMD] Linked %s -> %s", discordId.c_str(), mcName.c_str());
            char resp[128];
            snprintf(resp, sizeof(resp), "LINKED %s -> %s\n", discordId.c_str(), mcName.c_str());
            sendto(g_udpSocket, resp, (int)strlen(resp), 0, (sockaddr*)from, sizeof(*from));
        } else {
            const char* err = "ERR: format L<discordId>:<mcName>\n";
            sendto(g_udpSocket, err, (int)strlen(err), 0, (sockaddr*)from, sizeof(*from));
        }
    }
    else if (data[0] == 'U') {
        // Unlink command: U<discordId>
        std::string discordId(data + 1, len - 1);
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(g_linkMutex);
            auto it = g_discordToMcName.find(discordId);
            if (it != g_discordToMcName.end()) {
                g_discordToMcName.erase(it);
                found = true;
            }
        }
        DebugLog("[CMD] Unlinked %s (%s)", discordId.c_str(), found ? "found" : "not found");
        char resp[128];
        snprintf(resp, sizeof(resp), "UNLINKED %s (%s)\n", discordId.c_str(), found ? "ok" : "not found");
        sendto(g_udpSocket, resp, (int)strlen(resp), 0, (sockaddr*)from, sizeof(*from));
    }
    else if (data[0] == 'Q') {
        const char* ack = "UNLOADING\n";
        sendto(g_udpSocket, ack, (int)strlen(ack), 0, (sockaddr*)from, sizeof(*from));
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            // 1. Stop hooks from processing (pass-through only)
            bool expected = false;
            if (!g_shutdownFlag.compare_exchange_strong(expected, true)) return 0;
            Sleep(200); // let in-flight hook calls finish

#if DEBUG_LOG_ENABLED
            // 2. Stop console thread first (before freeing DLL code)
            StopConsoleThread();
#endif

            // 3. Stop playback thread (also cleans up shared memory)
            g_audioManager.running = false;
            bool playbackStopped = true;
            if (g_audioManager.playbackThread) {
                playbackStopped = (WaitForSingleObject(g_audioManager.playbackThread, 3000) == WAIT_OBJECT_0);
                CloseHandle(g_audioManager.playbackThread);
                g_audioManager.playbackThread = nullptr;
            }

            // 4. Remove hooks (safe now, no threads using them)
            CleanupHooks();

            // 5. Cleanup OpenAL (only if playback thread fully stopped)
            if (playbackStopped) g_audioManager.DestroyAudio();

            // 6. Stop UDP
            StopUdpReceiver();

#if DEBUG_LOG_ENABLED
            HWND hConsole = GetConsoleWindow();
            FreeConsole();
            if (hConsole) PostMessage(hConsole, WM_CLOSE, 0, 0);
#endif
            FreeLibraryAndExitThread(g_hModule, 0);
            return 0;
        }, nullptr, 0, nullptr);
    }
}

static DWORD WINAPI UdpReceiverThread(LPVOID) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    g_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udpSocket == INVALID_SOCKET) { WSACleanup(); return 1; }

    sockaddr_in bindAddr = {};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(UDP_LISTEN_PORT);
    bindAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(g_udpSocket, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        closesocket(g_udpSocket);
        g_udpSocket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    DWORD timeout = 500;
    setsockopt(g_udpSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    char buf[256];
    while (g_udpRunning) {
        sockaddr_in from = {};
        int fromLen = sizeof(from);
        int len = recvfrom(g_udpSocket, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fromLen);
        if (len > 0) HandleUdpCommand(buf, len, &from);
    }

    if (g_udpSocket != INVALID_SOCKET) {
        closesocket(g_udpSocket);
        g_udpSocket = INVALID_SOCKET;
    }
    WSACleanup();
    return 0;
}

void StartUdpReceiver() {
    g_udpRunning = true;
    g_udpThread = CreateThread(nullptr, 0, UdpReceiverThread, nullptr, 0, nullptr);
}

void StopUdpReceiver() {
    g_udpRunning = false;
    // Close socket to unblock recvfrom immediately
    SOCKET s = g_udpSocket;
    if (s != INVALID_SOCKET) {
        g_udpSocket = INVALID_SOCKET;
        closesocket(s);
    }
    if (g_udpThread) {
        WaitForSingleObject(g_udpThread, 3000);
        CloseHandle(g_udpThread);
        g_udpThread = nullptr;
    }
}

//------------------------------------------
// Console (debug only)
//------------------------------------------
#if DEBUG_LOG_ENABLED
static std::atomic<bool> g_consoleRunning{ false };
static HANDLE g_consoleThread = nullptr;

static void InitializeConsole() {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONIN$", "r", stdin);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONOUT$", "w", stdout);
    SetConsoleTitle(L"PJ_DM_Core Debug Console");
}

static void StopConsoleThread() {
    g_consoleRunning = false;
    // Cancel blocking ReadConsoleA by closing stdin handle
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin != INVALID_HANDLE_VALUE) CancelSynchronousIo(hStdin);
    if (g_consoleThread) {
        WaitForSingleObject(g_consoleThread, 1000);
        CloseHandle(g_consoleThread);
        g_consoleThread = nullptr;
    }
}

static DWORD WINAPI ConsoleCommandThread(LPVOID) {
    char buffer[256];
    DWORD read;
    while (g_consoleRunning) {
        if (ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), buffer, sizeof(buffer) - 1, &read, NULL)) {
            if (!g_consoleRunning) break;
            buffer[read] = '\0';
            for (DWORD i = 0; i < read; i++) {
                if (buffer[i] == '\r' || buffer[i] == '\n') { buffer[i] = '\0'; break; }
            }
            if (strcmp(buffer, "De") == 0) {
                bool expected = false;
                if (!g_shutdownFlag.compare_exchange_strong(expected, true)) break;
                Sleep(200);
                StopUdpReceiver();
                g_audioManager.running = false;
                if (g_audioManager.playbackThread) {
                    WaitForSingleObject(g_audioManager.playbackThread, 2000);
                    CloseHandle(g_audioManager.playbackThread);
                    g_audioManager.playbackThread = nullptr;
                }
                CleanupHooks();
                g_audioManager.DestroyAudio();
                HWND hConsole = GetConsoleWindow();
                FreeConsole();
                if (hConsole) PostMessage(hConsole, WM_CLOSE, 0, 0);
                FreeLibraryAndExitThread(g_hModule, 0);
            }
            else if (strncmp(buffer, "link ", 5) == 0) {
                // link <discordId> <mcName>
                char* args = buffer + 5;
                char* space = strchr(args, ' ');
                if (space && space > args && *(space + 1)) {
                    std::string discordId(args, space - args);
                    std::string mcName(space + 1);
                    {
                        std::lock_guard<std::mutex> lock(g_linkMutex);
                        g_discordToMcName[discordId] = mcName;
                        g_linkResolvePending.erase(discordId);
                        g_linkResolveRetryAt.erase(discordId);
                    }
                    DebugLog("[CMD] Linked %s -> %s", discordId.c_str(), mcName.c_str());
                } else {
                    DebugLog("Usage: link <discordId> <mcName>");
                }
            }
            else if (strncmp(buffer, "unlink ", 7) == 0) {
                std::string discordId(buffer + 7);
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(g_linkMutex);
                    auto it = g_discordToMcName.find(discordId);
                    if (it != g_discordToMcName.end()) {
                        g_discordToMcName.erase(it);
                        found = true;
                    }
                }
                DebugLog("[CMD] Unlinked %s (%s)", discordId.c_str(), found ? "found" : "not found");
            }
            else if (strcmp(buffer, "links") == 0) {
                std::lock_guard<std::mutex> lock(g_linkMutex);
                DebugLog("=== Discord -> MC Name ===");
                for (auto& p : g_discordToMcName)
                    DebugLog("  %s -> %s", p.first.c_str(), p.second.c_str());
                if (g_discordToMcName.empty()) DebugLog("  (empty)");
            }
            else if (strcmp(buffer, "list") == 0) {
                std::lock_guard<std::mutex> lock(g_audioManager.dataMutex);
                DebugLog("=== SSRC -> UserID ===");
                for (auto& p : g_audioManager.ssrcToUserId)
                    DebugLog("  %u -> %s", (unsigned)p.first, p.second.c_str());
                DebugLog("=== Audio Sources ===");
                for (auto& p2 : g_audioManager.userAudioMap)
                    DebugLog("  SSRC=%u", (unsigned)p2.first);
            }
        }
        Sleep(100);
    }
    return 0;
}
#endif

//------------------------------------------
// Main initialization
//------------------------------------------
static DWORD WINAPI InitThread(LPVOID) {
#if DEBUG_LOG_ENABLED
    InitializeConsole();
    DebugLog("PJ_DM_Core attached");
#else
    Sleep(500);
#endif

    if (!g_audioManager.Initialize()) {
        DebugLog("OpenAL init failed");
        return 1;
    }

    g_audioManager.StartPlayback();

    if (!InitializeHooks()) {
        DebugLog("Hook init failed");
        g_audioManager.running = false;
        if (g_audioManager.playbackThread) {
            WaitForSingleObject(g_audioManager.playbackThread, 3000);
            CloseHandle(g_audioManager.playbackThread);
            g_audioManager.playbackThread = nullptr;
        }
        g_audioManager.DestroyAudio();
        FreeLibraryAndExitThread(g_hModule, 0);
        return 1;
    }

    StartUdpReceiver();

#if DEBUG_LOG_ENABLED
    g_consoleRunning = true;
    g_consoleThread = CreateThread(nullptr, 0, ConsoleCommandThread, nullptr, 0, nullptr);
#endif

    return 0;
}

//------------------------------------------
// DLL Entry Point
//------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        { HANDLE h = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr); if (h) CloseHandle(h); }
        break;
    case DLL_PROCESS_DETACH:
        g_shutdownFlag = true;
#if DEBUG_LOG_ENABLED
        StopConsoleThread();
#endif
        g_audioManager.running = false;
        bool pbStopped = true;
        if (g_audioManager.playbackThread) {
            pbStopped = (WaitForSingleObject(g_audioManager.playbackThread, 2000) == WAIT_OBJECT_0);
            CloseHandle(g_audioManager.playbackThread);
            g_audioManager.playbackThread = nullptr;
        }
        CleanupHooks();
        if (pbStopped) g_audioManager.DestroyAudio();
        StopUdpReceiver();
#if DEBUG_LOG_ENABLED
        { HWND c = GetConsoleWindow(); FreeConsole(); if (c) PostMessage(c, WM_CLOSE, 0, 0); }
#endif
        break;
    }
    return TRUE;
}
