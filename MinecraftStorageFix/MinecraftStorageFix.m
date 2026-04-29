//
//  MinecraftStorageFix.m
//  MinecraftStorageFix
//
//  Fixes iCloud, CloudKit, storage crashes, and the mandatory iCloud sign-in
//  gate in Minecraft for Apple TV.
//  Target: com.mojang.minecraftappletv (tvOS 15+)
//
//  =========================================================================
//  IDA Pro analysis of Minecraft_1.1.5_decrypted
//  =========================================================================
//
//  CONFIRMED selectors / strings in the binary (IDA string table):
//    0x101412ba9  "defaultContainer"
//    0x101412c9b  "accountStatusWithCompletionHandler:"
//    0x101412be2  "privateCloudDatabase"
//    0x101412bba  "fetchUserRecordIDWithCompletionHandler:"
//    0x101412af6  "initWithStorage:"
//    0x101412b07  "mStorage"
//    0x101412ad4  "iCloudAccountAvailabilityChanged:"
//    0x1013d9a9d  "com.mojang.minecraftappletv.UbiquityIdentityToken"
//    0x10141509d  "iCloudNotificationListener"
//
//  =========================================================================
//  CRASH ANALYSIS (Layers 1-4, pre-existing fixes)
//  =========================================================================
//
//  Crash #1 — sub_100CA2DA4 (accountStatusWithCompletionHandler: callback):
//    Unconditionally dereferences iCloudStorage::Impl* before status check.
//    On sideloaded builds Impl* is null → EXC_BAD_ACCESS.
//
//  Crash #2 — sub_100CA17B4 (fetchUserRecordIDWithCompletionHandler: callback):
//    Same Impl* null dereference; writes NSUserDefaults key.
//
//  Crash #3 — iCloudAccountAvailabilityChanged: ObjC trigger:
//    Registered for NSUbiquityIdentityDidChangeNotification AND
//    CKAccountChangedNotification. Both fire on sideloaded builds, triggering
//    the crash path. No-op swizzle blocks both notifications.
//
//  =========================================================================
//  iCLOUD SIGN-IN GATE ANALYSIS (Layers 5 & 7)
//  =========================================================================
//
//  After the crashes above are fixed the game displays a mandatory
//  "Sign in to iCloud" dialog and refuses to proceed. This is driven by two
//  C++ vtable-dispatched gate functions:
//
//  Gate 1 — sub_100240C60 at vtable entry 0x1014A4B58:
//    v1   = *(int64_t *)(a1 + 8)          // AppPlatform_apple *
//    v2   = sub_100361214(*(v1 + 632))    // iCloud manager from StorageProvider
//    if (!(vtable[3](v2)) || !(sub_10035C990(v1+632) & 1)):
//        sub_10035C938(sp, callback, 0)   // Permissions = 3 → sign-in dialog
//    else:
//        sub_10035A088(sp)                // SUCCESS → sub_10013F3F8 → main menu
//
//    sub_10035A088(sp) accesses *(sp+32) (local FileInterface).
//    sub_10000EFD8 reads *(sp+32) unconditionally → null guard is required.
//
//  Gate 2 — sub_1001D083C at vtable entry 0x10149C410:
//    Identical iCloud check; success path calls sub_10035E93C(sp, 1) which
//    calls sub_1000204A8(*(sp+24), 1). *(sp+24) is the iCloud-specific
//    sub-object that may be null when iCloud is not configured → null guard.
//
//  Gate 3 — sub_10024FA94 at vtable entry 0x1014A5758  (PREVIOUSLY MISSED):
//    v1   = *(int64_t *)(a1 + 8)          // AppPlatform_apple *
//    obj  = *(int64_t *)(v1 + 704)        // loader/world-progress object
//    NOTE: uses platform+704, NOT platform+632 (StorageProvider)
//    iCloud check → if unavailable: v5=1 → sub_10035C938 → "Turn on iCloud"
//    Success helpers: sub_100359EA8, sub_10035F334, sub_100437624, sub_100430C98
//
//  IDA confirmed ALL THREE gates as the only callers of sub_10035C938 via
//  get_xrefs_to(0x10035C938):
//    0x1001d08b8 — sub_1001D083C   (Gate 2) ✓ patched
//    0x100240cd8 — sub_100240C60   (Gate 1) ✓ patched
//    0x10024fb60 — sub_10024FA94   (Gate 3) ✓ patched in this version
//
//  ADDITIONAL GATE (Layer 7 — Permissions dispatcher):
//    sub_1000206AC (vtable 0x101489df8) is a 2169-line loading tick function
//    that bypasses sub_10035C938 and calls sub_10013EB6C(*(a1+584), 3, ...)
//    DIRECTLY when iCloud is unavailable.  sub_100032C60 (via vtable
//    sub_1006F1848 at 0x1014d3c90) also calls sub_10013EB6C with arbitrary
//    Permissions values.
//    Every Permissions observer — regardless of which code path created it —
//    dispatches through sub_100244B60 at vtable slot 0x1014A5150.  Replacing
//    this dispatcher so it always calls the success path (sub_100359918) is
//    the nuclear option that covers all present and future dialog triggers.
//
//  VTABLE PATCH STRATEGY:
//    Make the __DATA_CONST page momentarily writable with vm_protect, replace
//    the function pointer in each vtable slot with our bypass stub, then
//    restore read-only protection.  The bypass stubs null-check all pointers
//    before calling the game's own success handlers.  On W^X-enforced builds
//    vm_protect fails silently — Layers 1-4 remain active so the game does
//    not crash; it will still show the dialog.
//
//  =========================================================================
//  SYSTEM iCLOUD PROMPT (Layer 6, URLForUbiquityContainerIdentifier:)
//  =========================================================================
//
//  tvOS can show a native "Sign in to iCloud" sheet before the game's own
//  dialog if the app requests an iCloud container URL and no account is
//  present.  Redirecting URLForUbiquityContainerIdentifier: to a local path
//  prevents the system sheet.  The selector was not found as a literal in the
//  binary — this hook is precautionary.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdarg.h>
#import <stdio.h>
#import <dirent.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <unistd.h>
#include <string.h>
#import "fishhook.h"

// ---------------------------------------------------------------------------
//  Layer 6c — sub_1006E64E0 @0x1006E64E0 (storage root a3)
//
//  fishhook / rebind_symbols only affect lazy-bound *imports* (e.g. open(2)).
//  The game’s own text symbol sub_1006E64E0 is not rebindable via fishhook.
//  Not hooked — no inline hooking runtime (ElleKit/Substrate) is used.
//  The fishhook POSIX layer and NSFileManager swizzle catch all I/O instead.
//
//  MCPEDeviceID (IDA: KeychainItemWrapper in sub_1006E64E0) uses the keychain,
//  not the a3 filesystem root — redirecting a3 does not reset the device id.
// ---------------------------------------------------------------------------

// SecTask is not in the public tvOS SDK; load symbols at runtime from Security.framework.
typedef void *MinecraftStorageFix_SecTaskRef;
typedef MinecraftStorageFix_SecTaskRef (*MinecraftStorageFix_SecTaskCreateFromSelf_t)(void *allocator);
typedef CFTypeRef (*MinecraftStorageFix_SecTaskCopyValueForEntitlement_t)(MinecraftStorageFix_SecTaskRef task, CFStringRef key, void *errorOut);

static MinecraftStorageFix_SecTaskCreateFromSelf_t          mcfix_SecTaskCreateFromSelf          = NULL;
static MinecraftStorageFix_SecTaskCopyValueForEntitlement_t mcfix_SecTaskCopyValueForEntitlement = NULL;

static void MCFIXResolveSecTaskIfAvailable(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        if (!sec) {
            return;
        }
        mcfix_SecTaskCreateFromSelf =
            (MinecraftStorageFix_SecTaskCreateFromSelf_t)dlsym(sec, "SecTaskCreateFromSelf");
        mcfix_SecTaskCopyValueForEntitlement =
            (MinecraftStorageFix_SecTaskCopyValueForEntitlement_t)dlsym(
                sec, "SecTaskCopyValueForEntitlement");
    });
}

// ---------------------------------------------------------------------------
//  Xbox / MSA keychain (IDA: -[XBLKeychainStorage dictionaryForKeychainQuery:]
//  @ ~0x101099764; literal "com.microsoft.xboxliveservices" is kSecAttrService;
//  kSecAttrAccessGroup is only set if _accessGroup is non-nil.)
//  Sideloads see securityd -34018 when the access group is not entitled.
//  We do NOT use dyld __interpose on SecItem* (can crash the whole process).
//  We only replace the single method IMP above and rewrite kSecAttrAccessGroup
//  in the returned query when it references com.microsoft.xboxliveservices.
//  Remap target uses AppIdentifierPrefix (any TEAM + any bundle) or SecTask
//  application-identifier, then UserDefaults, then a suffix-only fallback.
// ---------------------------------------------------------------------------

typedef id (*XBL_DictionaryForQuery_t)(id, SEL, id);
static XBL_DictionaryForQuery_t gXBLKeychainStorage_orig_dictForQuery = NULL;

// NOTE (Layer 3): +[CKContainer defaultContainer] → nil stub via swizzle.
// IDA: sub_100CA2C40 @0x100ca2c84 BL _objc_msgSend(defaultContainer), then
//      -[CKContainer accountStatusWithCompletionHandler:] on X20.
// sub_100CA2DA4: completion dereferences iCloudStorage::Impl* at *(a1+32).
// If that runs with null Impl* → EXC_BAD_ACCESS. Nil receiver skips the callback.
// Forwarding to Apple’s IMP caused EXC_BREAKPOINT under _dispatch_once_callout
// on some builds (re-entrant singleton init). Other layers supply progression.

static NSString *MCFIXMinecraftMainBundleId(void) {
    NSString *b = [NSBundle mainBundle].bundleIdentifier;
    return (b.length > 0) ? b : @"com.mojang.minecraftappletv";
}

/// 10-char team from the *running* app’s "application-identifier" entitlement
/// (TEAM.bundleid) — works when Info.plist has no AppIdentifierPrefix (some sideloads).
static NSString *MCFIXTeamIdFromSecTaskApplicationIdentifier(void) {
    MCFIXResolveSecTaskIfAvailable();
    if (!mcfix_SecTaskCreateFromSelf || !mcfix_SecTaskCopyValueForEntitlement) {
        return nil;
    }
    MinecraftStorageFix_SecTaskRef task = mcfix_SecTaskCreateFromSelf((void *)kCFAllocatorDefault);
    if (!task) {
        return nil;
    }
    CFTypeRef v = mcfix_SecTaskCopyValueForEntitlement(
        task, CFSTR("application-identifier"), NULL);
    CFRelease((CFTypeRef)task);
    if (!v) {
        return nil;
    }
    if (CFGetTypeID(v) != CFStringGetTypeID()) {
        CFRelease(v);
        return nil;
    }
    NSString *s = (__bridge NSString *)v;
    NSRange d = [s rangeOfString:@"."];
    NSString *out = (d.location > 0) ? [s substringToIndex:d.location] : nil;
    CFRelease(v);
    return out.length > 0 ? out : nil;
}

static NSString *MCFIXRemapXboxKeychainAccessGroup(NSString *accessGroup) {
    if (accessGroup.length == 0) {
        return nil;
    }
    if ([accessGroup rangeOfString:@"com.microsoft.xboxliveservices"].location == NSNotFound) {
        return nil;
    }
    NSString *ov = [[NSUserDefaults standardUserDefaults]
        stringForKey:@"MinecraftStorageFixXboxKeychainGroup"];
    if (ov.length > 0) {
        return ov;
    }
    NSString *team = nil;
    id prefix = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppIdentifierPrefix"];
    if ([prefix isKindOfClass:[NSString class]] && [(NSString *)prefix length] > 0) {
        team = [(NSString *)prefix
            stringByTrimmingCharactersInSet:
                [NSCharacterSet characterSetWithCharactersInString:@". "]];
    }
    if (team.length == 0) {
        team = MCFIXTeamIdFromSecTaskApplicationIdentifier();
    }
    if (team.length > 0) {
        return [NSString stringWithFormat:@"%@.%@", team, MCFIXMinecraftMainBundleId()];
    }
    // Last resort: only swaps the "com.microsoft…" tail for the current bundle id;
    // the team prefix in the string may still be Mojang’s (works only if that team is entitled).
    NSRange r = [accessGroup rangeOfString:@"com.microsoft.xboxliveservices"];
    if (r.location == NSNotFound) {
        return nil;
    }
    return [accessGroup stringByReplacingCharactersInRange:r
                                              withString:MCFIXMinecraftMainBundleId()];
}

static id mcfix_xbl_replacement_dictForKeychainQuery(id self, SEL _cmd, id key) {
    if (!gXBLKeychainStorage_orig_dictForQuery) {
        return nil;
    }
    id d = gXBLKeychainStorage_orig_dictForQuery(self, _cmd, key);
    if (!d) {
        return d;
    }
    NSMutableDictionary *m = [d isKindOfClass:[NSMutableDictionary class]]
        ? d
        : [d mutableCopy];
    if (![m isKindOfClass:[NSMutableDictionary class]]) {
        return d;
    }
    id ag = m[(id)kSecAttrAccessGroup];
    if (![ag isKindOfClass:[NSString class]]) {
        return m;
    }
    NSString *remapped = MCFIXRemapXboxKeychainAccessGroup((NSString *)ag);
    if (remapped.length > 0) {
        m[(id)kSecAttrAccessGroup] = remapped;
    }
    return m;
}

// ---------------------------------------------------------------------------
//  Xbox Live Login (XBLMSADeviceClient)
//  The game uses -[XBLMSADeviceClient msaAppID] as OAuth client_id, built as
//  ios-app://<CFBundleIdentifier>. Sideloads get HTTP 400 unless this matches
//  the app registration; force the retail Mojang id for the device-code flow.
// ---------------------------------------------------------------------------
static NSString *mcfix_msaAppID_replacement(id self, SEL _cmd) {
    (void)self;
    (void)_cmd;
    return @"ios-app://com.mojang.minecraftappletv";
}

// ---------------------------------------------------------------------------
//  Game storage VFS — tvOS sideload sandbox (NSFileManager paths only)
//
//  Observed kernel denials on device (minecraftappletv):
//    deny(1) file-write-create .../Library/Application Support
//    deny(1) file-write-create .../Documents/games
//  The previous build used NSApplicationSupportDirectory for the redirect root,
//  which calls into the system to *create* "Application Support" — that hits
//  the first denial.  "Documents/games" was never redirected, so ensureGameData
//  and the engine still touched the real Documents tree.
//
//  Fix: never touch Application Support for this layer.  Re-home paths under
//  $HOME/Library/Caches/MinecraftStorageFix/GameData/vfs/<tail> where <tail>
//  is the substring after $HOME/ for:
//    • Library/games/...   (IDA: "games/com.mojang/" @0x1013bec96,
//                           "/games/com.mojang/" @0x1013c4849,
//                           "/games/com.mojang/minecraftStructures/" @0x1013d7dc5)
//    • Documents/games/...
//  So on disk we mirror e.g. .../vfs/Library/games/com.mojang/... under Caches.
//  Caches is writable in strict profiles where App Support / Documents/games
//  are not (we already use Caches for app-group + iCloud sim shims).
//
//  vtable / CloudKit / XBL: unchanged.  Pure POSIX I/O is still not redirected.
//
//  -------------------------------------------------------------------------
//  IDA Pro trace (Minecraft Apple TV, preferred base 0x100000000) — MCP
//  The binary does *not* store a full absolute "Library/.../com.mojang" path;
//  it stores *relative* fragments and joins them in C++ to the container root.
//
//  • InitFunc_2083 @0x100794ef0 — static init: qword_101656F80 = std::string
//    "/games/com.mojang/" (literal in __text @0x1013c4849, length 0x12).
//  • sub_1006E64E0 @0x1006E64E0 (large ctor) — after copying storage root a3
//    onto (a1+456), builds a path: base + *global* qword_101656F80 via
//    std::string::append @ ~0x1006E6860-0x1006E687C, result → (a1+528).  So
//    the in-game "com mojang" root is: <root> + "/games/com.mojang/".
//  • InitFunc_1752 @0x100692528 — qword_1016549F8 = "games/com.mojang/" (0x11),
//    plus "minecraftWorlds/", "worlds/", etc. (sibling std::string globals).
//  • sub_10069216C @0x10069216C — if (!(a1+144)): concatenates *a1 base +
//    qword_1016549F8 + qword_101654A10 ("minecraftWorlds/") @0x1006921E8+.
//  The platform layer supplies <root> ending in .../Library/ or .../Documents/,
//  so the resolved path is always under $HOME/Library/games/... *or*
//  $HOME/Documents/games/... — exactly the two tail prefixes the swizzle
//  remaps to .../Library/Caches/.../GameData/vfs/...
//  -------------------------------------------------------------------------

static int mcfix_orig_mkdir_p(const char *path, mode_t mode);

static int (*mcfix_orig_mkdir)(const char *path, mode_t mode) = NULL;
static int (*mcfix_orig_access)(const char *path, int amode) = NULL;

static NSString *MCFIXGameDataVFSSandboxRoot(void) {
    static NSString *root;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // NSCachesDirectory only — do NOT use NSApplicationSupportDirectory here.
        NSFileManager *fm = [NSFileManager defaultManager];
        NSURL *u = [fm URLForDirectory:NSCachesDirectory
                            inDomain:NSUserDomainMask
                   appropriateForURL:nil
                              create:YES
                               error:nil];
        NSString *caches = u.path;
        if (caches.length == 0) {
            caches = [NSSearchPathForDirectoriesInDomains(
                NSCachesDirectory, NSUserDomainMask, YES) firstObject];
        }
        if (caches.length == 0) {
            caches = [[[NSHomeDirectory() stringByStandardizingPath]
                stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"Caches"];
        }
        root = [[[[caches stringByAppendingPathComponent:@"MinecraftStorageFix"]
            stringByAppendingPathComponent:@"GameData"] stringByAppendingPathComponent:@"vfs"]
            stringByStandardizingPath];
        const char *gr = root.fileSystemRepresentation;
        if (gr) {
            int mk = mcfix_orig_mkdir_p(gr, (mode_t)0755);
            if (mk != 0 && (mcfix_orig_mkdir == NULL || mcfix_orig_access == NULL)) {
                (void)[fm createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
            }
        }
    });
    return root;
}

/// True for normal POSIX file paths (leading `/`). Does not treat `file://` as absolute; game paths are always filesystem strings here.
static BOOL MCFIXStringIsAbsolutePOSIXPath(NSString *s) {
    if (s.length == 0) {
        return NO;
    }
    return [s hasPrefix:@"/"];
}

static BOOL MCFIXTailNeedsGameVFSCacheRedirect(NSString *tail) {
    if (tail.length == 0) {
        return NO;
    }
    static NSArray<NSString *> *prefixes;
    static dispatch_once_t ponce;
    dispatch_once(&ponce, ^{
        prefixes = @[
            @"Library/games",
            @"Documents/games",
            // Real runtime roots when sub_1006E64E0 is NOT hooked (framework-only).
            // IDA confirmed: sub_100C9BCEC builds NSTemporaryDirectory()+"Temp" and
            // passes it as a3 to sub_1006E64E0. All POSIX save I/O (fopen, rename,
            // remove) originates from this root. Tail relative to NSHomeDirectory().
            @"tmp/Temp/games",
            @"tmp/Temp/internal",
            // IDA confirmed: sub_100792D10 builds a1+312 = a1+480 + "/minecraftpe"
            // where a1+480 = NSTemporaryDirectory() (raw, no /Temp suffix).
            // Tail relative to NSHomeDirectory() = "tmp/minecraftpe".
            // Covers pack cache, screenshots, and any secondary content roots
            // stored at this location (used with the "minecraftpe/" global segment
            // from InitFunc_1752 @0x100692528 / InitFunc_2087 @0x1007965e0).
            @"tmp/minecraftpe",
        ];
    });
    for (NSString *pre in prefixes) {
        if ([tail isEqualToString:pre]) {
            return YES;
        }
        if ([tail hasPrefix:pre] && [tail length] > [pre length] &&
            [tail characterAtIndex:pre.length] == (unichar)'/') {
            return YES;
        }
    }
    return NO;
}

static NSString *MCFIXPathByRedirectingGameStorage(NSString *path) {
    if (path.length == 0) {
        return path;
    }
    // Bedrock may chdir(2) to the container and use relative paths (e.g. "games/com.mojang/...").
    // those never pass hasPrefix:home until absolutized (relative-path blind spot).
    NSString *std = [path stringByStandardizingPath];
    if (!MCFIXStringIsAbsolutePOSIXPath(std)) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            NSString *cwdStr = [NSString stringWithUTF8String:cwd];
            if (cwdStr != nil) {
                std = [[cwdStr stringByAppendingPathComponent:std] stringByStandardizingPath];
            }
        }
    }
    NSString *home = [NSHomeDirectory() stringByStandardizingPath];
    if (home.length == 0) {
        return path;
    }
    // On tvOS NSHomeDirectory() returns /var/mobile/... but kernel-level paths reported
    // to POSIX hooks (from stat/rename/open/etc.) carry the /private/var/mobile/... form
    // because /var is a symlink to /private/var. Build an alternate prefix so we match
    // whichever form the incoming path uses.
    NSString *homeForMatch = home;
    if ([std hasPrefix:@"/private/"] && ![home hasPrefix:@"/private/"]) {
        homeForMatch = [@"/private" stringByAppendingString:home];
    } else if (![std hasPrefix:@"/private/"] && [home hasPrefix:@"/private/"]) {
        // "/private" is 8 chars.
        homeForMatch = [home substringFromIndex:8];
    }
    if (![std hasPrefix:homeForMatch]) {
        // Diagnostic: log paths that look like save data but escaped our prefix check.
        if ([path containsString:@"level.dat"] || [path containsString:@"minecraftWorlds"] ||
            [path containsString:@"levelname"] || [path containsString:@"MANIFEST"] ||
            [path containsString:@"CURRENT"] || [path containsString:@"tmp/Temp/games"]) {
            NSLog(@"[MCFIX REDIRECT MISS] path=%@ home=%@ std=%@", path, home, std);
        }
        return path;
    }
    NSString *tail;
    if ([std isEqualToString:homeForMatch]) {
        tail = @"";
    } else if (std.length == homeForMatch.length + 1) {
        unichar c = [std characterAtIndex:homeForMatch.length];
        if (c == (unichar)'/') {
            tail = [std substringFromIndex:homeForMatch.length + 1];
        } else {
            return path;
        }
    } else if ([std hasPrefix:homeForMatch] && [std length] > [homeForMatch length] &&
               [std characterAtIndex:homeForMatch.length] == (unichar)'/') {
        tail = [std substringFromIndex:homeForMatch.length + 1];
    } else {
        return path;
    }
    if (!MCFIXTailNeedsGameVFSCacheRedirect(tail)) {
        // If we absolutized a relative path with getcwd(3), return `std` so
        // NSFileManager and POSIX hooks see a path consistent with the check
        // above, not the original unqualified relative string.
        if (!MCFIXStringIsAbsolutePOSIXPath(path)) {
            return std;
        }
        return path;
    }
    NSString *vfs  = MCFIXGameDataVFSSandboxRoot();
    NSString *dest = [NSString stringWithFormat:@"%@/%@", vfs, tail];
    NSString *redirected = [dest stringByStandardizingPath];
    // Save-path diagnostic: log any redirect that touches world or level data.
    if ([tail containsString:@"tmp/Temp/games"] ||
        [path containsString:@"minecraftWorlds"] ||
        [path containsString:@"level.dat"] ||
        [path containsString:@"MANIFEST"] ||
        [path containsString:@"CURRENT"]) {
        NSLog(@"[MCFIX SAVE REDIRECT] %@ -> %@", path, redirected);
    }
    return redirected;
}

static NSURL *MCFIXFileURLByRedirectingGameStorage(NSURL *url) {
    if (![url isFileURL]) {
        return url;
    }
    NSString *p = MCFIXPathByRedirectingGameStorage(url.path);
    if ([p isEqualToString:url.path] || p.length == 0) {
        return url;
    }
    return [NSURL fileURLWithPath:p];
}

// ---------------------------------------------------------------------------
//  Layer 6b — fishhook: POSIX (C++) path rebinding
//
//  Bedrock often uses C++ fstreams / libc open/mkdir without NSFileManager.
//  rebind_symbols() patches __DATA __la_symbol_ptr / __nl_symbol_ptr in all
//  loaded images.  Same redirect as Layer 6a (MCFIXPathByRedirectingGameStorage).
//
//  Path logic: MCFIXPathByRedirectingGameStorage absolutizes *relative* paths
//  with getcwd(3) before hasPrefix:home, so chdir + open("games/...") works.
//
//  Apple 64-bit libc often uses stat$INODE64, lstat$INODE64, fopen$DARWIN_EXTSN,
//  opendir$INODE64 — each needs its own mcfix_orig_* (fishhook overwrites one
//  slot per name; shared "replaced" pointers would clobber).  readdir/closedir
//  are not rebound (no path argument).
//
//  IDA (MCP list_imports): _open, _mkdir, _access, _fopen, _lstat, _stat,
//  _rename, _unlink, _chmod, _rmdir, _remove, _opendir, _readdir, …;
//  suffixed symbols may not appear in the import list but are still rebound
//  when present in a dylib IAT.
// ---------------------------------------------------------------------------

static const char *MCFIXPOSIXResolvedPathForSyscall(const char *cPath, char fspath[PATH_MAX]) {
    if (cPath == NULL) {
        return NULL;
    }
    @autoreleasepool {
        NSString *ns = [NSString stringWithUTF8String:cPath];
        if (ns == nil) {
            return NULL;
        }
        NSString *res = MCFIXPathByRedirectingGameStorage(ns);
        if ([res isEqualToString:ns]) {
            return cPath;
        }
        if (![res getFileSystemRepresentation:fspath maxLength:(NSUInteger)PATH_MAX]) {
            return NULL;
        }
        return fspath;
    }
}
static int (*mcfix_orig_open)(const char *path, int oflag, ...) = NULL;
static FILE *(*mcfix_orig_fopen)(const char *path, const char *mode) = NULL;static int (*mcfix_orig_stat)(const char *path, struct stat *sb) = NULL;
static int (*mcfix_orig_lstat)(const char *path, struct stat *sb) = NULL;
static int (*mcfix_orig_unlink)(const char *path) = NULL;
static int (*mcfix_orig_rmdir)(const char *path) = NULL;
static int (*mcfix_orig_rename)(const char *oldpath, const char *newpath) = NULL;
static int (*mcfix_orig_chmod)(const char *path, mode_t mode) = NULL;
static int (*mcfix_orig_chown)(const char *path, uid_t owner, gid_t group) = NULL;
static int (*mcfix_orig_remove)(const char *path) = NULL;
static int (*mcfix_orig_statfs)(const char *path, struct statfs *buf) = NULL;
static int (*mcfix_orig_symlink)(const char *name1, const char *name2) = NULL;
static int (*mcfix_orig_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
static int (*mcfix_orig_openat)(int fd, const char *path, int oflag, ...) = NULL;
static int (*mcfix_orig_stat_inode64)(const char *path, struct stat *sb) = NULL;
static int (*mcfix_orig_lstat_inode64)(const char *path, struct stat *sb) = NULL;
static FILE *(*mcfix_orig_fopen_darwin_extsn)(const char *path, const char *mode) = NULL;
static DIR *(*mcfix_orig_opendir)(const char *path) = NULL;
static DIR *(*mcfix_orig_opendir_inode64)(const char *path) = NULL;

/// mkdir -p using only lazily-bound libc symbols (never NSFileManager). Avoids
/// re-entrancy: NSFileManager's createDirectoryAtPath invokes POSIX mkdir, which is
/// fishhooked — calling NSFileManager from inside open/fopen/rename hooks could
/// recurse through our mcfix_posix_mkdir / stack blow or deadlock.
static int mcfix_orig_mkdir_p(const char *path, mode_t mode) {
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_mkdir == NULL || mcfix_orig_access == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t L = strlen(tmp);
    while (L > 1 && tmp[L - 1] == '/') {
        tmp[--L] = '\0';
    }
    for (char *q = tmp + 1; *q; q++) {
        if (*q != '/') {
            continue;
        }
        *q = '\0';
        if (strlen(tmp) && strcmp(tmp, "/") != 0) {
            if (mcfix_orig_access(tmp, F_OK) != 0) {
                if (mcfix_orig_mkdir(tmp, mode) != 0 && errno != EEXIST) {
                    *q = '/';
                    return -1;
                }
            }
        }
        *q = '/';
    }
    if (strlen(tmp)) {
        if (mcfix_orig_access(tmp, F_OK) != 0) {
            int mk = mcfix_orig_mkdir(tmp, mode);
            if (mk != 0 && errno != EEXIST && errno != EISDIR) {
                return -1;
            }
        }
    }
    return 0;
}

typedef int (*MCFIXPosixPathStatFn)(const char *path, struct stat *sb);

static int mcfix_posix_xstat(const char *path, struct stat *sb, MCFIXPosixPathStatFn orig) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (sb == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (orig == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return orig(p, sb);
}

static int mcfix_posix_stat(const char *path, struct stat *sb) {
    return mcfix_posix_xstat(path, sb, mcfix_orig_stat);
}

static int mcfix_posix_stat_inode64(const char *path, struct stat *sb) {
    return mcfix_posix_xstat(path, sb, mcfix_orig_stat_inode64);
}

static int mcfix_posix_lstat(const char *path, struct stat *sb) {
    return mcfix_posix_xstat(path, sb, mcfix_orig_lstat);
}

static int mcfix_posix_lstat_inode64(const char *path, struct stat *sb) {
    return mcfix_posix_xstat(path, sb, mcfix_orig_lstat_inode64);
}

static int mcfix_posix_mkdir(const char *path, mode_t mode) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_mkdir == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_mkdir(p, mode);
}

static int mcfix_posix_open(const char *path, int oflag, ...) {
    mode_t cmode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        cmode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_open == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (oflag & O_CREAT) {
        int fd = mcfix_orig_open(p, oflag, cmode);
        if (fd == -1 && errno == ENOENT && (oflag & O_WRONLY || oflag & O_RDWR)) {
            NSString *ps = [NSString stringWithUTF8String:p];
            NSString *parent = [ps stringByDeletingLastPathComponent];
            const char *pdir = parent.fileSystemRepresentation;
            if (pdir && mcfix_orig_mkdir_p(pdir, (mode_t)0755) == 0) {
                fd = mcfix_orig_open(p, oflag, cmode);
            }
        }
        return fd;
    }
    return mcfix_orig_open(p, oflag);
}

static FILE *mcfix_fopen_impl(const char *path, const char *mode,
                              FILE *(*orig)(const char *, const char *)) {
    if (path == NULL || mode == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (orig == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return NULL;
    }
    FILE *result = orig(p, mode);
    // If opening for write/append failed with ENOENT the parent directory is missing
    // in the Caches VFS tree — create it and retry. This handles world folders that
    // were not yet created via our mkdir hook (e.g. race during first-time world creation).
    if (result == NULL && errno == ENOENT &&
        (mode[0] == 'w' || mode[0] == 'a' || (mode[0] == 'r' && strchr(mode, '+')))) {
        NSString *ps = [NSString stringWithUTF8String:p];
        NSString *parent = [ps stringByDeletingLastPathComponent];
        const char *pdir = parent.fileSystemRepresentation;
        if (pdir && mcfix_orig_mkdir_p(pdir, (mode_t)0755) == 0) {
            result = orig(p, mode);
        }
    }
    return result;
}

static FILE *mcfix_posix_fopen(const char *path, const char *mode) {
    return mcfix_fopen_impl(path, mode, mcfix_orig_fopen);
}

static FILE *mcfix_posix_fopen_darwin_extsn(const char *path, const char *mode) {
    return mcfix_fopen_impl(path, mode, mcfix_orig_fopen_darwin_extsn);
}

static int mcfix_posix_access(const char *path, int amode) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_access == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_access(p, amode);
}

static DIR *mcfix_opendir_impl(const char *path, DIR *(*orig)(const char *)) {
    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (orig == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return NULL;
    }
    return orig(p);
}

static DIR *mcfix_posix_opendir(const char *path) {
    return mcfix_opendir_impl(path, mcfix_orig_opendir);
}

static DIR *mcfix_posix_opendir_inode64(const char *path) {
    return mcfix_opendir_impl(path, mcfix_orig_opendir_inode64);
}

// ---------------------------------------------------------------------------
//  Anti-wipe protection helpers
//
//  The game's sync-commit path runs a full recursive deletion of the world
//  folder at quit/save time (log-confirmed at 23:10:37 in save issue33.txt):
//    rmdir minecraftWorlds/My World
//    remove FzkAAOY7AAAG/level.dat_old, world_icon.jpeg, world_behavior_packs.json,
//           levelname.txt, db/000015.log, db/000014.ldb, …, db/MANIFEST-000013,
//           db/LOCK, db/CURRENT   →   rmdir db/   →   remove level.dat
//  The game expects to re-download everything from cloud on next launch, but
//  our CKContainer bypass means that never happens, so the world is gone.
//
//  Fix: intercept every remove()/rmdir() on a path inside minecraftWorlds.
//  - Allow LevelDB's own housekeeping (WAL .log files, LOCK, .dbtmp, dat backups).
//  - Block everything else (silently return 0 so the caller thinks it succeeded).
// ---------------------------------------------------------------------------

static int MCFIXShouldBlockRemove(const char *p) {
    if (!p || !strstr(p, "minecraftWorlds")) return 0;
    const char *slash = strrchr(p, '/');
    const char *fn    = slash ? slash + 1 : p;
    // LevelDB housekeeping — allowed:
    if (strcmp(fn, "LOCK") == 0)           return 0; // open/close sequence
    if (strcmp(fn, "level.dat_new") == 0)  return 0; // cleaned after atomic rename
    if (strcmp(fn, "level.dat_old") == 0)  return 0; // cleaned after atomic rename
    if (strstr(fn, ".dbtmp"))              return 0; // dbtmp temp files
    // WAL log files — allowed (000003.log etc, but NOT "level.dat")
    if (strstr(fn, ".log") && strncmp(fn, "level", 5) != 0) return 0;
    // Everything else inside minecraftWorlds is world-identity or DB data — block.
    return 1;
}

static int MCFIXShouldBlockRmdir(const char *p) {
    // Block rmdir of any directory that lives inside minecraftWorlds.
    // World folders (FzkAAOY7AAAG, My World, …) and their sub-dirs (db, …)
    // must never be recursively removed by the sync-commit wipe.
    return p && strstr(p, "minecraftWorlds") != NULL;
}

static int mcfix_posix_unlink(const char *path) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_unlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    // Apply the same anti-wipe protection as mcfix_posix_remove — the game
    // may call unlink() directly rather than remove() for the same files.
    if (MCFIXShouldBlockRemove(p)) {
        NSLog(@"[MCFIX UNLINK BLOCKED] %s", p);
        return 0;
    }
    if (strstr(p, "minecraftWorlds") || strstr(p, "level.dat") ||
        strstr(p, "MANIFEST") || strstr(p, "CURRENT") ||
        strstr(p, ".ldb") || strstr(p, "LOCK")) {
        NSLog(@"[MCFIX UNLINK] %s", p);
    }
    return mcfix_orig_unlink(p);
}

static int mcfix_posix_rmdir(const char *path) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_rmdir == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (MCFIXShouldBlockRmdir(p)) {
        NSLog(@"[MCFIX RMDIR BLOCKED] %s", p);
        return 0; // lie to the wipe — directory stays intact
    }
    if (strstr(p, "com.mojang")) {
        NSLog(@"[MCFIX RMDIR] %s", p);
    }
    return mcfix_orig_rmdir(p);
}

static int mcfix_posix_rename(const char *oldpath, const char *newpath) {
    if (oldpath == NULL || newpath == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_rename == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char bo[PATH_MAX];
    char bn[PATH_MAX];
    const char *po = MCFIXPOSIXResolvedPathForSyscall(oldpath, bo);
    const char *pn = MCFIXPOSIXResolvedPathForSyscall(newpath, bn);
    if (po == NULL || pn == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Verbose logging for save-critical renames so we can trace the exact paths.
    BOOL isSavePath = (strstr(oldpath, "level.dat") || strstr(newpath, "level.dat") ||
                       strstr(oldpath, "levelname") || strstr(newpath, "levelname") ||
                       strstr(oldpath, "MANIFEST") || strstr(newpath, "MANIFEST") ||
                       strstr(oldpath, "CURRENT") || strstr(newpath, "CURRENT") ||
                       strstr(oldpath, "minecraftWorlds") || strstr(newpath, "minecraftWorlds"));
    if (isSavePath) {
        NSLog(@"[MCFIX RENAME] raw: %s -> %s | redirected: %s -> %s",
              oldpath, newpath, po, pn);
    }

    int result = mcfix_orig_rename(po, pn);

    if (isSavePath) {
        NSLog(@"[MCFIX RENAME RESULT] %d errno=%d for %s -> %s",
              result, result == 0 ? 0 : errno, po, pn);
    }

    if (result != 0) {
        @autoreleasepool {
            NSString *vfs = MCFIXGameDataVFSSandboxRoot();
            NSString *poStr = [NSString stringWithUTF8String:po];
            NSString *pnStr = [NSString stringWithUTF8String:pn];
            BOOL poIsInCaches = [poStr hasPrefix:vfs];
            BOOL pnIsInCaches = [pnStr hasPrefix:vfs];

            if (poIsInCaches && !pnIsInCaches) {
                // po is already in the Caches VFS root (e.g. LevelDB resolved its db dir
                // internally) but pn is still the original tmp/Temp/... path.
                // Derive the correct Caches destination two ways and try both:
                //   1. MCFIXPathByRedirectingGameStorage on the raw newpath (now works
                //      correctly after the /private/var fix).
                //   2. Same-directory derivation: replace po's filename with pn's filename.
                NSString *rawNew = [NSString stringWithUTF8String:newpath];
                NSString *correctDest = MCFIXPathByRedirectingGameStorage(rawNew);
                if ([correctDest isEqualToString:rawNew]) {
                    // Redirect still failed for newpath — use same-directory derivation.
                    NSString *poDir = [poStr stringByDeletingLastPathComponent];
                    NSString *pnName = [pnStr lastPathComponent];
                    correctDest = [poDir stringByAppendingPathComponent:pnName];
                    NSLog(@"[MCFIX RENAME FALLBACK SAMEDIR] derived dest: %@", correctDest);
                }
                NSString *correctParent = [correctDest stringByDeletingLastPathComponent];
                const char *pdir = correctParent.fileSystemRepresentation;
                if (pdir) {
                    (void)mcfix_orig_mkdir_p(pdir, (mode_t)0755);
                }
                const char *correctC = [correctDest fileSystemRepresentation];
                if (correctC) {
                    result = mcfix_orig_rename(po, correctC);
                    NSLog(@"[MCFIX RENAME FALLBACK] %s -> %s result=%d errno=%d",
                          po, correctC, result, result == 0 ? 0 : errno);
                }

            } else if (!poIsInCaches && po != oldpath) {
                // po was redirected by MCFIX (po != oldpath) but pn was not redirected to
                // Caches. Try redirecting newpath explicitly.
                NSString *rawNew = [NSString stringWithUTF8String:newpath];
                NSString *correctDest = MCFIXPathByRedirectingGameStorage(rawNew);
                if ([correctDest isEqualToString:rawNew]) {
                    // Still no redirect — fall back to same-directory derivation.
                    NSString *poDir = [NSString stringWithUTF8String:po];
                    poDir = [poDir stringByDeletingLastPathComponent];
                    NSString *pnName = [[NSString stringWithUTF8String:newpath] lastPathComponent];
                    correctDest = [poDir stringByAppendingPathComponent:pnName];
                    NSLog(@"[MCFIX RENAME FALLBACK2 SAMEDIR] derived dest: %@", correctDest);
                }
                NSString *correctParent = [correctDest stringByDeletingLastPathComponent];
                const char *pdir2 = correctParent.fileSystemRepresentation;
                if (pdir2) {
                    (void)mcfix_orig_mkdir_p(pdir2, (mode_t)0755);
                }
                const char *correctC = [correctDest fileSystemRepresentation];
                if (correctC) {
                    result = mcfix_orig_rename(po, correctC);
                    NSLog(@"[MCFIX RENAME FALLBACK2] %s -> %s result=%d errno=%d",
                          po, correctC, result, result == 0 ? 0 : errno);
                }
            }
        }
    }

    // If rename succeeded but pn is outside Caches while po was in Caches,
    // copy the result back to the correct Caches location (achievement icons etc
    // are harmless, but world files must land in Caches).
    if (result == 0 && isSavePath) {
        @autoreleasepool {
            NSString *vfs = MCFIXGameDataVFSSandboxRoot();
            NSString *pnStr = [NSString stringWithUTF8String:pn];
            if (![pnStr hasPrefix:vfs]) {
                NSString *rawNew = [NSString stringWithUTF8String:newpath];
                NSString *correctDest = MCFIXPathByRedirectingGameStorage(rawNew);
                if (![correctDest isEqualToString:rawNew]) {
                    NSString *correctParent = [correctDest stringByDeletingLastPathComponent];
                    NSFileManager *fm = [NSFileManager defaultManager];
                    const char *repairDir = correctParent.fileSystemRepresentation;
                    if (repairDir) {
                        (void)mcfix_orig_mkdir_p(repairDir, (mode_t)0755);
                    }
                    NSError *copyErr = nil;
                    [fm copyItemAtPath:pnStr toPath:correctDest error:&copyErr];
                    if (!copyErr) {
                        NSLog(@"[MCFIX RENAME REPAIR] Copied %@ -> %@", pnStr, correctDest);
                    } else {
                        NSLog(@"[MCFIX RENAME REPAIR FAIL] %@ -> %@: %@",
                              pnStr, correctDest, copyErr.localizedDescription);
                    }
                }
            }
        }
    }

    return result;
}

static int mcfix_posix_chmod(const char *path, mode_t mode) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_chmod == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_chmod(p, mode);
}

static int mcfix_posix_chown(const char *path, uid_t owner, gid_t group) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_chown == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_chown(p, owner, group);
}

static int mcfix_posix_remove(const char *path) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_remove == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (MCFIXShouldBlockRemove(p)) {
        NSLog(@"[MCFIX REMOVE BLOCKED] %s", p);
        return 0; // lie to the wipe — file stays on disk
    }
    if (strstr(p, "minecraftWorlds") || strstr(p, "level.dat") ||
        strstr(p, "MANIFEST") || strstr(p, "CURRENT") ||
        strstr(p, ".ldb") || strstr(p, "LOCK")) {
        NSLog(@"[MCFIX REMOVE] %s", p);
    }
    return mcfix_orig_remove(p);
}

static int mcfix_posix_statfs(const char *path, struct statfs *buf) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_statfs == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char fspath[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, fspath);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_statfs(p, buf);
}

static int mcfix_posix_symlink(const char *name1, const char *name2) {
    if (name1 == NULL || name2 == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_symlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char b2[PATH_MAX];
    const char *p2 = MCFIXPOSIXResolvedPathForSyscall(name2, b2);
    if (p2 == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_symlink(name1, p2);
}

static int mcfix_posix_readlink(const char *path, char *buf, size_t bufsiz) {
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_readlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char fspath[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, fspath);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mcfix_orig_readlink(p, buf, bufsiz);
}

static int mcfix_posix_openat(int fd, const char *path, int oflag, ...) {
    mode_t cmode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        cmode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mcfix_orig_openat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    char buf[PATH_MAX];
    const char *p = MCFIXPOSIXResolvedPathForSyscall(path, buf);
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (oflag & O_CREAT) {
        int outfd = mcfix_orig_openat(fd, p, oflag, cmode);
        if (outfd == -1 && errno == ENOENT && (oflag & O_WRONLY || oflag & O_RDWR)) {
            NSString *ps = [NSString stringWithUTF8String:p];
            NSString *parent = [ps stringByDeletingLastPathComponent];
            const char *pdir = parent.fileSystemRepresentation;
            if (pdir && mcfix_orig_mkdir_p(pdir, (mode_t)0755) == 0) {
                outfd = mcfix_orig_openat(fd, p, oflag, cmode);
            }
        }
        return outfd;
    }
    return mcfix_orig_openat(fd, p, oflag);
}

// ---------------------------------------------------------------------------
//  Binary offsets (preferred load address 0x100000000)
// ---------------------------------------------------------------------------

// Gate 1: sub_100240C60 — success handler sub_10035A088
//   a1+8=platform, platform+632=storageProvider
static const uintptr_t kVtableSlot1     = 0x1014A4B58UL;
static const uintptr_t kSuccessFunc1    = 0x10035A088UL;

// Gate 2: sub_1001D083C — success handler sub_10035E93C
//   a1+8=platform, platform+632=storageProvider
static const uintptr_t kVtableSlot2     = 0x10149C410UL;
static const uintptr_t kSuccessFunc2    = 0x10035E93CUL;

// Gate 3: sub_10024FA94 — triggers "Turn on iCloud" dialog; vtable 0x1014A5758
//   a1+8=platform, platform+704=loadObj (DIFFERENT field from gates 1&2)
//   Failure: sub_10035C938(loadObj, cb, 0) → Permissions=3 → in-game dialog
//   Success path helpers:
//     sub_100359EA8(loadObj, 0)   — state update (called in BOTH paths)
//     sub_10035F334(loadObj)      — get screen object (= sub_10001F838(*(loadObj+24)))
//     sub_100437624(screenObj, n) — screen progression (ignores args, reads globals)
//     sub_100430C98()             — iCloud KV sync cleanup (reads globals, no args)
static const uintptr_t kVtableSlot3     = 0x1014A5758UL;
static const uintptr_t kFnStateUpdate3  = 0x100359EA8UL;
static const uintptr_t kFnScreenObj3    = 0x10035F334UL;
static const uintptr_t kFnProgression3  = 0x100437624UL;
static const uintptr_t kFnKVCleanup3   = 0x100430C98UL;

// Layer 7: Permissions observer dispatcher — sub_100244B60 at vtable 0x1014A5150
//   Dispatches on *(observer+698):
//     case 0 → sub_100359918(*(observer+632))  SUCCESS
//     case 2 → sub_100244D90(a1)               "iCloud no space" dialog
//     case 3 → sub_100244BF4(a1)               "sign-in required" dialog
//     default→ sub_100244F0C(a1)               "iCloud disabled" dialog
//   In every case the original calls sub_1001562E4(a1) AFTER the handler — this
//   is the observer notification chain that unblocks waiting subscribers.
//   IDA-confirmed: 0x1014A5150 bytes = 0x60 0x4b 0x24 0x00 0x01... = 0x100244B60
static const uintptr_t kDispatcherSlot    = 0x1014A5150UL;

// IO streaming callback null-guard — sub_100C6EAC4 at vtable 0x10154A3C8
//   Call chain (IDA-confirmed):
//     IO Thread loop sub_10079EB84
//       → sub_10079CEC0 (IO work dispatcher)
//         → sub_10079B82C checks *(work+40), calls vtable[6] = sub_100C6EAC4
//           → sub_100C6EAC4(a1):
//               sub_100C70D50( *(*(a1+24) + 72) )
//           → sub_100C70D50(streamObj):
//               (*(vtable**)(**vtable*)(streamObj+104) + 32)(&result)  ← SIGSEGV
//
//   Crash: *(streamObj+104) == null — the sub-interface pointer in the streaming
//   handler object is null (game race condition: object allocated but sub-interface
//   not yet assigned, OR freed while IO operation still queued).
//   Confirmed: EXC_BAD_ACCESS KERN_INVALID_ADDRESS 0x0, IO Thread(0), ~16 s in.
//   FAR=0 → null vtable dereference. x0=0 at crash PC 0x100C70D70.
//
//   Fix: replace the vtable slot with a wrapper that null-guards all pointers.
//   If any guard fails we return 1 (treated as "done") so the IO queue drains
//   normally — the missing streaming result is recoverable (resource reload).
static const uintptr_t kIoCallbackSlot   = 0x10154A3C8UL;
// IO batch callback null-guard — sub_100C6E47C at vtable 0x10154A348
//   Call chain (IDA-confirmed):
//     quit/save path dispatcher
//       → vtable slot 0x10154A348 = sub_100C6E47C
//         → sub_100C6E548 (thread-local worker init), then
//         → sub_100C70D50( *(*(a1+8) + 72) )    ← same crash
//             → (*(streamObj+104) + 32)(…)        ← SIGSEGV at *(streamObj+104)==0
//
//   Same root cause as Layer 8 but called during world quit/save via a second
//   vtable slot.  IDA-confirmed: sub_100C6E47C is the only DATA xref from 0x10154A348.
//   Pointer chain differs from Layer 8: a1+8 → v2, v2+72 → streamObj, streamObj+104 → null.
static const uintptr_t kIoCallbackSlot2  = 0x10154A348UL;
// LevelDB sync system no-op — sub_100CA795C at vtable 0x10154C5E0
//   Call chain (IDA-confirmed):
//     LevelDB internal sync trigger
//       → vtable slot 0x10154C5E0 = sub_100CA795C
//         → creates "-SYNC-N" backup copies of DB files (e.g. MANIFEST-000002-SYNC-000001)
//         → sub_100CA76B4 (sync completion handler)
//           → sub_100CA0948 with "modifyFileBatch"
//             → sub_100C9F6C0 → CloudKit dispatch (CKContainer returns nil → error)
//
//   When CloudKit fails, a cleanup path may delete the world's local files,
//   causing the world to vanish after app restart. Replacing this vtable slot
//   with a no-op prevents -SYNC- file creation and the entire CloudKit upload
//   chain, eliminating the "failed to sync world data" error and the associated
//   post-failure cleanup. LevelDB still operates normally on the primary files.
static const uintptr_t kSyncSlot         = 0x10154C5E0UL;
// sub_100CA9838  — queryAllAssetsForProvider trigger.
// Called (via vtable) whenever a world is opened; immediately issues a
// CKQueryOperation against the private database.  With [CKContainer
// defaultContainer] returning nil the database object is also nil, so the
// operation's completion handler fires at once with an error → the sync
// state machine dispatches status=7 to the main thread → the game shows
// "failed to sync world data" and enters a cloud-write mode where writes
// are buffered for upload instead of going to disk (changes are lost on exit).
// IDA: xref DATA at 0x10154C698 → sub_100CA9838.  Confirmed by
//   data_read_qword(0x10154C698) == 0x100CA9838.
static const uintptr_t kNoQuerySlot      = 0x10154C698UL;
// sub_100CA9074  — "remove all assets" queue trigger.
// Called (via vtable) when the sync state machine decides to wipe local
// world files and re-download from cloud.  Queues TWO "remove all assets"
// actions via sub_100CA1138 → sub_100C9F6C0, which eventually drives
// sub_100CA551C to call POSIX remove/rmdir on every file inside the world
// directory.  The POSIX-level anti-wipe (Layer 12) already blocks these
// calls at the syscall boundary; this patch stops them before they are
// even queued, eliminating any state-machine side-effects.
// IDA: xref DATA at 0x10154C5C8 → sub_100CA9074.  Confirmed by
//   data_read_qword(0x10154C5C8) == 0x100CA9074.
static const uintptr_t kNoWipeQueueSlot  = 0x10154C5C8UL;
static const uintptr_t kDispatcherSuccess = 0x100359918UL;
// sub_1001562E4 — observer notification chain, MUST be called after every
// Permissions dispatch (original calls it in every switch case).
// Skipping it leaves subscribers pending → use-after-free crash during world gen.
static const uintptr_t kNotifyChain       = 0x1001562E4UL;

// ---------------------------------------------------------------------------
//  NOT PATCHED (IDA): sub_100793354 vtable slot 0x10154BF18, and CloudKit query
//  dispatch slots 0x10154C4B0 / 0x10154C570 / 0x10154C578.
//
//  Baseline dylib (MinecraftStorageFix_works) reaches the menu with none of these
//  patched; patching them produced a white screen after become-active (logs
//  stillwhitescreen.txt: GL + ViewController + become-active OK, then stall).
//
//  IDA: sub_100CA5D10 (pointer in slot 0x10154C4B0) ends with `return v16()` after
//  setQueryCompletionBlock / addOperation — i.e. it must invoke a completion functor.
//  Replacing it with mcfix_syncSystemNoOp skipped that path, so sync/bootstrap never
//  advanced. sub_100CA718C / sub_100CA73B0 (0x10154C570 / 0x10154C578) likewise
//  call completion thunks (v12/v13 and v26/v27) that must run.
//
//  Gates already use mcfix_gateBypass1/2/3 and never consult sub_100793354; leaving
//  0x10154BF18 stock matches the working dylib and avoids extra divergence.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//  C++ bypass stubs (called from the patched vtable slots)
// ---------------------------------------------------------------------------

typedef int64_t (*SuccessFn1)(int64_t storageProvider);
typedef void    (*SuccessFn2)(int64_t storageProvider, int64_t flags);

// Replaces sub_100240C60.  Reads AppPlatform_apple* from a1+8, StorageProvider
// from platform+632, and calls sub_10035A088 which sets up the world-icon path
// and invokes sub_10013F3F8 to continue game initialization.
static int64_t mcfix_gateBypass1(int64_t a1) {
    if (!a1) return 0;

    int64_t platform = *(int64_t *)(a1 + 8);
    if (!platform) return 0;

    int64_t sp = *(int64_t *)(platform + 632);
    if (!sp) return 0;

    // sub_10035A088 calls sub_10000EFD8(*(sp+32)) unconditionally; guard it.
    if (!*(int64_t *)(sp + 32)) return 0;

    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);
    SuccessFn1 fn = (SuccessFn1)(kSuccessFunc1 + (uintptr_t)slide);
    return fn(sp);
}

// Replaces sub_1001D083C.  Calls sub_10035E93C(sp, 1) which forwards to
// sub_1000204A8(*(sp+24), 1) — guard the iCloud-specific sub-object at sp+24.
static int64_t mcfix_gateBypass2(int64_t a1) {
    if (!a1) return 0;

    int64_t platform = *(int64_t *)(a1 + 8);
    if (!platform) return 0;

    int64_t sp = *(int64_t *)(platform + 632);
    if (!sp) return 0;

    // sub_10035E93C → sub_1000204A8(*(sp+24), 1); guard the sub-object.
    if (!*(int64_t *)(sp + 24)) return 0;

    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);
    SuccessFn2 fn = (SuccessFn2)(kSuccessFunc2 + (uintptr_t)slide);
    fn(sp, 1);
    return 0;
}

// Replaces sub_10024FA94 — the third and final caller of sub_10035C938.
// This gate uses platform+704 (a loader/world-progress object), NOT the
// StorageProvider at +632.  When iCloud is unavailable the original function
// sets v5=1 and calls sub_10035C938 → "Turn on iCloud" dialog.
// Our bypass calls the same state-update helper that both paths call, then
// drives the success-path screen/progression helpers, and returns 8.
//
// sub_100359EA8 is IDA-confirmed called in BOTH the failure AND success paths,
// so it is always safe to call here.  sub_100437624 / sub_100430C98 read only
// game globals (qword_101651CD0, qword_101651CC8) — IDA shows them taking no
// parameters; any values we pass in registers are ignored by the callee.
static int64_t mcfix_gateBypass3(int64_t a1) {
    if (!a1) return 8;

    int64_t platform = *(int64_t *)(a1 + 8);
    if (!platform) return 8;

    int64_t obj704 = *(int64_t *)(platform + 704);
    if (!obj704) return 8;

    // sub_100359EA8 calls sub_10000EFD8(*(obj704+32)) — guard that field.
    if (!*(int64_t *)(obj704 + 32)) return 8;

    // IDA: sub_10035F334 → sub_10001F838(*(obj704+24)) derefs *(a1+480).
    // Stock crashes if +24 is NULL. Returning 8 when +24 was 0 skipped
    // sub_100359EA8 / progression and matched a white-screen stall (device
    // log: GL + become-active OK, then silence). Matches dylib that reaches UI:
    // always call the same helper sequence; do not early-exit on +24 alone.

    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);

    // State-update helper — called in both original paths.
    typedef int64_t (*FnStateUpdate)(int64_t, int64_t);
    ((FnStateUpdate)(kFnStateUpdate3 + (uintptr_t)slide))(obj704, 0);

    // Get the screen/progression object (sub_10035F334 = sub_10001F838(*(obj+24))).
    typedef int64_t (*FnScreenObj)(int64_t);
    int64_t screenObj = ((FnScreenObj)(kFnScreenObj3 + (uintptr_t)slide))(obj704);

    // Screen-progression helper (reads globals, ignores register args).
    typedef void (*FnProgression)(int64_t, int64_t);
    ((FnProgression)(kFnProgression3 + (uintptr_t)slide))(screenObj, (int64_t)0xFFFFFFFFLL);

    // iCloud KV sync cleanup (reads globals, no real parameters).
    typedef void (*FnKVCleanup)(void);
    ((FnKVCleanup)(kFnKVCleanup3 + (uintptr_t)slide))();

    return 8;
}

// Replaces CloudKit query/sync vtable slots (Layers 11, 13a, 13b).
// No-ops the entire chain so the sync state machine stays in idle state and
// never triggers the error dialog or cloud-write mode.
// WARNING: do NOT add NSLog or dispatch_once here. This function is called
// from C++ CloudKit init callbacks on threads that are part of the game's
// critical startup chain. Any lock acquisition (including os_log internals
// and dispatch_once spinlocks) can cause a startup deadlock / white screen.

// Replaces sub_100244B60 (Permissions observer dispatcher).
// Forces every Permissions value to the success path instead of showing a dialog.
//
// IDA CONFIRMED call sequence in the original (every switch case):
//   1. handler(a1) — dialog OR success depending on *(a1+698)
//   2. sub_1001562E4(a1) — observer notification chain (MANDATORY)
//
// The notification chain iterates subscribers at (a1+392..400) and notifies each.
// If we skip it, those subscribers are never woken, the observer object may be
// freed from another path while still referenced, causing a use-after-free SIGABRT
// during world generation (~24 s into runtime, right after XBL auth completes).
//
// sub_100359918(sp) call chain (IDA-traced):
//   sub_10000EFD8(*(sp+32)) → sub_10002BD58(*(ptr+48)) → *(ptr+584)
//   sub_10012C040(v1, 1)    → sub_10002BD44(*v1)       → sub_10016BBC8(*(v1+176))
//   sub_10016BBC8 body:      *(result+48) += 1          // counter increment only
// Calling it multiple times is safe — it only increments a permissions-granted counter.
typedef int64_t (*DispatchSuccessFn)(int64_t);
typedef int64_t (*NotifyChainFn)(int64_t);
static int64_t mcfix_permissionsForceSuccess(int64_t a1) {
    if (!a1) return 0;
    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);

    // Call the success handler (replace all dialog paths with success path).
    // Guard *(sp+32) just as sub_100359918 reads it unconditionally.
    int64_t sp = *(int64_t *)(a1 + 632);
    if (sp && *(int64_t *)(sp + 32)) {
        ((DispatchSuccessFn)(kDispatcherSuccess + (uintptr_t)slide))(sp);
    }

    // ALWAYS call the observer notification chain — original calls sub_1001562E4(a1)
    // in EVERY case.  Skipping this is the root cause of the world-gen SIGABRT.
    return ((NotifyChainFn)(kNotifyChain + (uintptr_t)slide))(a1);
}

// Replaces sub_100C6EAC4 (IO streaming completion callback, vtable slot 0x10154A3C8).
// Guards all pointer dereferences before the call to sub_100C70D50 so that the
// game's streaming race condition does not crash the process.
// When any pointer is null we return 1 (success/done) — the IO queue keeps draining
// and the game will reload the missing resource naturally.
static int64_t mcfix_safeIoCallback(int64_t a1) {
    if (!a1) return 1;
    int64_t ctx = *(int64_t *)(a1 + 24);
    if (!ctx) return 1;
    int64_t streamObj = *(int64_t *)(ctx + 72);
    if (!streamObj) return 1;
    // *(streamObj+104) is the sub-interface pointer whose null dereference is the crash.
    if (!*(int64_t *)(streamObj + 104)) {
        // Layer 10 (soft-freeze fix): mark this streaming object "done" so the poll
        // function sub_100C72988 short-circuits.  Without this write, sub_100C72988
        // sees *(v1+104)==0 and returns 0 forever → Streaming Pool shutdown deadlock.
        // sub_100C72988 checks *(BYTE*)(v1+240) first; if non-zero it returns 1 (done)
        // and never reads *(v1+104).  IDA-confirmed: the only writer of this flag in
        // the normal path is the streaming manager teardown; our early-exit skips it,
        // so we set it here to prevent the infinite spin-wait.
        *(int8_t *)(streamObj + 240) = 1;
        return 1;
    }
    // All guards passed — call original function directly by address.
    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);
    typedef int64_t (*IoCallbackFn)(int64_t);
    return ((IoCallbackFn)(0x100C6EAC4UL + (uintptr_t)slide))(a1);
}

// Replaces sub_100C6E47C (IO batch callback, vtable slot 0x10154A348).
// Called during the world quit/save path.  The pointer chain here is
//   a1 → +8 → v2 → +72 → streamObj → +104 → sub-interface (null = crash).
// Guards all four pointers; if any is null returns 1 (done) so the IO
// queue drains safely.  When all guards pass, calls the original directly.
static int64_t mcfix_safeIoCallback2(int64_t a1) {
    if (!a1) return 1;
    int64_t v2 = *(int64_t *)(a1 + 8);
    if (!v2) return 1;
    int64_t streamObj = *(int64_t *)(v2 + 72);
    if (!streamObj) return 1;
    if (!*(int64_t *)(streamObj + 104)) {
        // Layer 10 (soft-freeze fix): same deadlock guard as mcfix_safeIoCallback.
        // sub_100C72988 (poll function, vtable 0x10154A6A8) checks *(BYTE*)(v1+240)
        // first; non-zero → return 1 (done).  If we skip this write, +104==0 causes
        // the poll to return 0 forever, deadlocking the Streaming Pool shutdown wait.
        *(int8_t *)(streamObj + 240) = 1;
        return 1;
    }
    intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(0);
    typedef int64_t (*IoCallback2Fn)(int64_t);
    return ((IoCallback2Fn)(0x100C6E47CUL + (uintptr_t)slide))(a1);
}

// Replaces sub_100CA795C (LevelDB sync vtable slot 0x10154C5E0).
// The real function creates "-SYNC-N" backup copies of DB files then dispatches
// a CloudKit modifyFileBatch operation via sub_100CA76B4→sub_100CA0948.
// Even with a live `+[CKContainer defaultContainer]`, this upload path can fail
// on sideloads and the failure cleanup can delete local world data. This no-op stops
// the entire chain at its source: no backups, no upload, no cleanup.
// LevelDB continues writing to the primary files in NSCachesDirectory normally.
static int64_t mcfix_syncSystemNoOp(int64_t a1, unsigned char *a2) {
    (void)a1; (void)a2;
    return 0;
}

// ---------------------------------------------------------------------------
//  Vtable patcher (makes one __DATA_CONST pointer writable, swaps it, locks)
// ---------------------------------------------------------------------------

static BOOL mcfix_patchVtableSlot(uintptr_t staticSlotAddr, void *newFn) {
    intptr_t  slide   = (intptr_t)_dyld_get_image_vmaddr_slide(0);
    void    **slot    = (void **)(staticSlotAddr + (uintptr_t)slide);
    uintptr_t pageBase = (uintptr_t)slot & ~((uintptr_t)vm_page_size - 1);

    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)pageBase,
                                  (vm_size_t)vm_page_size,
                                  FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        // Log which patches succeed or fail so we know which regions are writable.
        NSLog(@"[MCFIX VTABLE] FAIL slot=0x%lx fn=%p kr=0x%x (%s)",
              staticSlotAddr, newFn, kr,
              kr == KERN_PROTECTION_FAILURE ? "KERN_PROTECTION_FAILURE" :
              kr == KERN_INVALID_ADDRESS    ? "KERN_INVALID_ADDRESS"    :
              kr == KERN_NO_ACCESS          ? "KERN_NO_ACCESS"          : "other");
        return NO;
    }

    *slot = newFn;

    vm_protect(mach_task_self(),
               (vm_address_t)pageBase,
               (vm_size_t)vm_page_size,
               FALSE,
               VM_PROT_READ);
    NSLog(@"[MCFIX VTABLE] OK   slot=0x%lx fn=%p", staticSlotAddr, newFn);
    return YES;
}

// ---------------------------------------------------------------------------

NSString *MCFIXMinecraftSavesBasePath(void) {
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *err = nil;
        // tvOS sideload sandbox: NSApplicationSupportDirectory with create:YES can hit
        // kernel deny(... file-write-create .../Library/Application Support) → EPERM
        // Code 513. That mirrors MCFIXGameDataVFSSandboxRoot — use NSCachesDirectory only.
        NSURL *u = [fm URLForDirectory:NSCachesDirectory
                            inDomain:NSUserDomainMask
                   appropriateForURL:nil
                              create:YES
                               error:&err];
        NSString *caches = u.path;
        if (caches.length == 0) {
            caches = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
        }
        if (caches.length == 0) {
            caches = [[[NSHomeDirectory() stringByStandardizingPath]
                stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"Caches"];
        }
        path = [[[caches stringByAppendingPathComponent:@"MinecraftStorageFix"]
            stringByAppendingPathComponent:@"MinecraftSaves"] stringByStandardizingPath];
        err = nil;
        const char *psm = path.fileSystemRepresentation;
        if (psm && mcfix_orig_mkdir_p(psm, (mode_t)0755) != 0) {
            if (![fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&err] && err) {
                NSLog(@"[MinecraftStorageFix] MinecraftSaves mkdir (Caches fallback): %@", err);
            }
        }
        (void)[[NSURL fileURLWithPath:path isDirectory:YES]
            setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    });
    return path;
}

const char *MCFIXMinecraftSavesBasePathUTF8(void) {
    static char buf[PATH_MAX];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *p = MCFIXMinecraftSavesBasePath();
        if (![p getFileSystemRepresentation:buf maxLength:sizeof(buf)]) {
            const char *u8 = p.UTF8String;
            if (u8) {
                (void)snprintf(buf, sizeof(buf), "%s", u8);
            } else {
                buf[0] = '\0';
            }
        }
    });
    return buf;
}

void MCFIXEnsureMinecraftSavesAndMigrateFromTempIfNeeded(void) {
    (void)MCFIXMinecraftSavesBasePath();
    // v2: base path moved Application Support → Caches (tvOS sideload EPERM on mkdir App Support).
    static NSString *const kMigratedTempKey = @"MinecraftStorageFix_6E64_migrated_games_com_mojang_v2";
    static NSString *const kMigratedLegacyASKey =
        @"MinecraftStorageFix_legacy_ApplicationSupport_MinecraftSaves_v2";

    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *newBase = MCFIXMinecraftSavesBasePath();
    NSString *newGames =
        [[[newBase stringByAppendingPathComponent:@"games"] stringByAppendingPathComponent:@"com.mojang"]
            stringByStandardizingPath];

    // 1) tmp/Temp/games/com.mojang → …/Caches/…/MinecraftSaves/games/com.mojang
    if (![defs boolForKey:kMigratedTempKey]) {
        NSString *tempRoot =
            [[NSTemporaryDirectory() stringByAppendingPathComponent:@"Temp"] stringByStandardizingPath];
        NSString *oldGames = [[[tempRoot stringByAppendingPathComponent:@"games"]
            stringByAppendingPathComponent:@"com.mojang"] stringByStandardizingPath];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:oldGames isDirectory:&isDir] && isDir &&
            !([fm fileExistsAtPath:newGames isDirectory:&isDir] && isDir)) {
            NSError *e = nil;
            if (![fm createDirectoryAtPath:newGames.stringByDeletingLastPathComponent
                     withIntermediateDirectories:YES
                                      attributes:nil
                                           error:&e]) {
                NSLog(@"[MinecraftStorageFix] mkdir parent for migrate: %@", e);
            }
            e = nil;
            if (![fm moveItemAtPath:oldGames toPath:newGames error:&e]) {
                NSLog(@"[MinecraftStorageFix] migrate games/com.mojang: %@", e);
            } else {
                NSLog(@"[MinecraftStorageFix] migrated %@ -> %@", oldGames, newGames);
            }
        }
        [defs setBool:YES forKey:kMigratedTempKey];
        [defs synchronize];
    }

    // 2) Older builds used Library/Application Support/MinecraftSaves — move once if present.
    if (![defs boolForKey:kMigratedLegacyASKey]) {
        BOOL destDir = NO;
        if ([fm fileExistsAtPath:newGames isDirectory:&destDir] && destDir) {
            [defs setBool:YES forKey:kMigratedLegacyASKey];
            [defs synchronize];
        } else {
            NSURL *asu = [fm URLForDirectory:NSApplicationSupportDirectory
                                     inDomain:NSUserDomainMask
                            appropriateForURL:nil
                                       create:NO
                                        error:nil];
            NSString *legacyGames = nil;
            if (asu.path.length > 0) {
                legacyGames =
                    [[[[asu.path stringByAppendingPathComponent:@"MinecraftSaves"]
                        stringByAppendingPathComponent:@"games"]
                        stringByAppendingPathComponent:@"com.mojang"] stringByStandardizingPath];
            }
            BOOL legDir = NO;
            if (legacyGames.length &&
                [fm fileExistsAtPath:legacyGames isDirectory:&legDir] && legDir) {
                NSError *e = nil;
                if ([fm createDirectoryAtPath:newGames.stringByDeletingLastPathComponent
                         withIntermediateDirectories:YES
                                          attributes:nil
                                               error:&e]) {
                    e = nil;
                    if ([fm moveItemAtPath:legacyGames toPath:newGames error:&e]) {
                        NSLog(@"[MinecraftStorageFix] migrated legacy %@", legacyGames);
                    } else {
                        NSLog(@"[MinecraftStorageFix] legacy App Support move: %@", e);
                    }
                }
            }
            [defs setBool:YES forKey:kMigratedLegacyASKey];
            [defs synchronize];
        }
    }
}

// ---------------------------------------------------------------------------
//  Sideload APS / User Notifications (IDA MCP)
//
//  String @0x1013c03b7: "Failed to register for notifications with error: %@\n"
//  Selector @0x1014107a3: registerForRemoteNotifications
//  (also didFail/DidRegister user-notification selectors in same blob @0x101410a*)
//
//  whitescreen2.txt: requestAuthorization succeeds, then NSCocoaErrorDomain 3000
//  "no valid aps-environment entitlement" when registering with apsd. Stub both
//  -[UIApplication registerForRemoteNotifications] and UNUserNotificationCenter
//  requestAuthorization to avoid entitlement / main-thread coupling on sideloads.
//
//  Entitlements in the IPA (.entitlements / provisioning) are still authoritative;
//  this complements them when Push cannot be enabled.
//
@interface UIApplication (MinecraftStorageFixPushStub)
@end
@implementation UIApplication (MinecraftStorageFixPushStub)
/// No apsd handshake (sideload sans aps-environment). Notify delegate with the same
/// NSCocoa error the game string-logs @0x1013c03b7 ("Failed to register...") so the
/// bootstrap can complete instead of waiting indefinitely for didRegister*.
- (void)mcfix_nop_registerForRemoteNotifications {
    UIApplication *app = [UIApplication sharedApplication];
    id del = app.delegate;
    SEL failSel = @selector(application:didFailToRegisterForRemoteNotificationsWithError:);
    if (del && [del respondsToSelector:failSel]) {
        NSError *err = [NSError errorWithDomain:NSCocoaErrorDomain code:3000 userInfo:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            void (*msg)(id, SEL, UIApplication *, NSError *) =
                (void (*)(id, SEL, UIApplication *, NSError *))objc_msgSend;
            msg(del, failSel, app, err);
        });
    }
}
@end

@interface UNUserNotificationCenter (MinecraftStorageFixAuthStub)
@end
@implementation UNUserNotificationCenter (MinecraftStorageFixAuthStub)
/// Skip system permission UI + async chain; satisfies bootstrap without blocking.
- (void)mcfix_requestAuthorizationFast:(UNAuthorizationOptions)options
                     completionHandler:(void (^)(BOOL granted, NSError *__nullable error))completionHandler {
    (void)options;
    if (!completionHandler) {
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        completionHandler(YES, nil);
    });
}
@end

@interface MinecraftStorageFix : NSObject
@end

@implementation MinecraftStorageFix

// fishhook: rebinds libc lazy-bound imports. This is the primary save-path
// redirect layer — all game POSIX I/O (fopen, rename, remove, open, mkdir…)
// is intercepted here. No inline hooking or ElleKit is used.
+ (void)installPOSIXPathRebindings {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        struct rebinding rebs[] = {
            {"mkdir",   (void *)mcfix_posix_mkdir,   (void **)&mcfix_orig_mkdir},
            {"open",    (void *)mcfix_posix_open,    (void **)&mcfix_orig_open},
            {"fopen",   (void *)mcfix_posix_fopen,   (void **)&mcfix_orig_fopen},
            {"fopen$DARWIN_EXTSN", (void *)mcfix_posix_fopen_darwin_extsn, (void **)&mcfix_orig_fopen_darwin_extsn},
            {"access",  (void *)mcfix_posix_access,  (void **)&mcfix_orig_access},
            {"stat",    (void *)mcfix_posix_stat,    (void **)&mcfix_orig_stat},
            {"stat$INODE64", (void *)mcfix_posix_stat_inode64, (void **)&mcfix_orig_stat_inode64},
            {"lstat",   (void *)mcfix_posix_lstat,   (void **)&mcfix_orig_lstat},
            {"lstat$INODE64", (void *)mcfix_posix_lstat_inode64, (void **)&mcfix_orig_lstat_inode64},
            {"opendir", (void *)mcfix_posix_opendir,  (void **)&mcfix_orig_opendir},
            {"opendir$INODE64", (void *)mcfix_posix_opendir_inode64, (void **)&mcfix_orig_opendir_inode64},
            {"unlink",  (void *)mcfix_posix_unlink,  (void **)&mcfix_orig_unlink},
            {"rmdir",   (void *)mcfix_posix_rmdir,   (void **)&mcfix_orig_rmdir},
            {"rename",  (void *)mcfix_posix_rename,  (void **)&mcfix_orig_rename},
            {"chmod",   (void *)mcfix_posix_chmod,   (void **)&mcfix_orig_chmod},
            {"chown",   (void *)mcfix_posix_chown,   (void **)&mcfix_orig_chown},
            {"remove",  (void *)mcfix_posix_remove,  (void **)&mcfix_orig_remove},
            {"statfs",  (void *)mcfix_posix_statfs,  (void **)&mcfix_orig_statfs},
            {"symlink", (void *)mcfix_posix_symlink, (void **)&mcfix_orig_symlink},
            {"readlink", (void *)mcfix_posix_readlink, (void **)&mcfix_orig_readlink},
            {"openat",  (void *)mcfix_posix_openat,  (void **)&mcfix_orig_openat},
        };
        (void)rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
    });
}

+ (void)patchSideloadPushAndUserNotifications {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class appCls = [UIApplication class];
        Method mReg = class_getInstanceMethod(appCls, @selector(registerForRemoteNotifications));
        Method mNop = class_getInstanceMethod(appCls, @selector(mcfix_nop_registerForRemoteNotifications));
        if (mReg && mNop) {
            method_exchangeImplementations(mReg, mNop);
        }
        Class unc = [UNUserNotificationCenter class];
        if (!unc) {
            return;
        }
        Method mAuth = class_getInstanceMethod(unc, @selector(requestAuthorizationWithOptions:completionHandler:));
        Method mFast = class_getInstanceMethod(
            unc, @selector(mcfix_requestAuthorizationFast:completionHandler:));
        if (mAuth && mFast) {
            method_exchangeImplementations(mAuth, mFast);
        }
    });
}

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Bootstrap order matches MinecraftStorageFix_works (reaches UI). POSIX +
        // migration + games NSFileManager must run before CloudKit swizzles so
        // early filesystem paths see hooks; CloudKit still before gate vtables.
        [self installPOSIXPathRebindings];
        MCFIXEnsureMinecraftSavesAndMigrateFromTempIfNeeded();
        [self patchNSFileManagerLibraryGamesPathRedirect];
        [self patchNSFileManagerStorage];
        [self patchNSFileManagerUbiquity];
        [self patchCloudKit];
        [self patchICloudNotificationListener];

        [self ensureGameDataDirectories];
        [self installUbiquityNotificationGuard];

        [self patchICloudGate];

        [self installXBLKeychainAccessGroupFixWithAttempt:0];
        [self patchXboxLoginClientID];

        // Push stub after save paths and gate patches (sideload notification failure).
        [self patchSideloadPushAndUserNotifications];

        // XBLMSADeviceClient may link after +load; re-apply (idempotent).
        dispatch_time_t t0 = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC));
        dispatch_after(t0, dispatch_get_main_queue(), ^{
            [MinecraftStorageFix patchXboxLoginClientID];
        });
        dispatch_time_t t1 = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC));
        dispatch_after(t1, dispatch_get_main_queue(), ^{
            [MinecraftStorageFix patchXboxLoginClientID];
        });
    });
}

+ (void)patchXboxLoginClientID {
    Class clientClass = objc_getClass("XBLMSADeviceClient");
    if (!clientClass) {
        return;
    }
    SEL sel = @selector(msaAppID);
    Method m = class_getInstanceMethod(clientClass, sel);
    if (m) {
        const char *enc = method_getTypeEncoding(m);
        if (enc == NULL) {
            enc = "@@:"; // - (id)msaAppID
        }
        class_replaceMethod(clientClass, sel, (IMP)mcfix_msaAppID_replacement, enc);
    }
}

/// Retries: XBLKeychainStorage may not be registered at +load time.
+ (void)installXBLKeychainAccessGroupFixWithAttempt:(NSInteger)attempt {
    static const NSInteger kMaxAttempts = 24;
    Class xbl = objc_getClass("XBLKeychainStorage");
    if (!xbl) {
        if (attempt < kMaxAttempts) {
            dispatch_after(
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                dispatch_get_main_queue(), ^{
                    [MinecraftStorageFix installXBLKeychainAccessGroupFixWithAttempt:attempt + 1];
                });
        }
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        SEL sel = @selector(dictionaryForKeychainQuery:);
        Method m = class_getInstanceMethod(xbl, sel);
        if (!m) {
            return;
        }
        const char *enc = method_getTypeEncoding(m);
        if (enc == NULL) {
            enc = "@@:@@";
        }
        IMP repl = (IMP)mcfix_xbl_replacement_dictForKeychainQuery;
        IMP willRun = class_getMethodImplementation(xbl, sel);
        if (willRun == NULL || willRun == repl) {
            return;
        }
        // MUST assign before class_replaceMethod: the new IMP is visible to other
        // threads immediately; if gXBL... is still NULL, we would return nil from the
        // replacement and break XBL/SecItem call sites that expect a dictionary.
        gXBLKeychainStorage_orig_dictForQuery = (XBL_DictionaryForQuery_t)willRun;
        (void)class_replaceMethod(xbl, sel, repl, enc);
    });
}

// ---------------------------------------------------------------------------
#pragma mark - Layers 5 & 7 — C++ iCloud Gate Vtable Bypass + Dispatcher Patch
// ---------------------------------------------------------------------------

+ (void)patchICloudGate {
    // Gates 1–3: prevent sub_10035C938 from ever being called.
    BOOL ok1 = mcfix_patchVtableSlot(kVtableSlot1, (void *)mcfix_gateBypass1);
    BOOL ok2 = mcfix_patchVtableSlot(kVtableSlot2, (void *)mcfix_gateBypass2);
    BOOL ok3 = mcfix_patchVtableSlot(kVtableSlot3, (void *)mcfix_gateBypass3);

    // Layer 7: Replace the Permissions dispatcher so that ANY observer created
    // with Permissions != 0 (e.g. from sub_1000206AC's direct path) still
    // takes the success branch instead of showing a dialog.
    BOOL ok7 = mcfix_patchVtableSlot(kDispatcherSlot, (void *)mcfix_permissionsForceSuccess);

    // Layer 8: IO streaming callback null-guard.
    // sub_100C6EAC4 (vtable 0x10154A3C8) crashes when *(streamObj+104) is null
    // due to a game race condition in the streaming/IO subsystem.  Our wrapper
    // null-checks every pointer in the chain and returns 1 (done) if any is null,
    // preventing the EXC_BAD_ACCESS SIGSEGV on the IO Thread (~16 s after launch).
    BOOL ok8 = mcfix_patchVtableSlot(kIoCallbackSlot, (void *)mcfix_safeIoCallback);

    // Layer 9: IO batch callback null-guard (quit/save path).
    // sub_100C6E47C (vtable 0x10154A348) is the second vtable slot that reaches
    // sub_100C70D50.  Triggered during world quit/save; same null *(streamObj+104)
    // race condition.  Pointer chain: a1+8 → v2, v2+72 → streamObj, streamObj+104.
    BOOL ok9 = mcfix_patchVtableSlot(kIoCallbackSlot2, (void *)mcfix_safeIoCallback2);

    // Layer 11: LevelDB sync system no-op.
    // Blocks sub_100CA795C (vtable 0x10154C5E0) from creating -SYNC- backup
    // files and triggering the CloudKit upload chain that results in a
    // "failed to sync world data" error and potential post-failure world deletion.
    BOOL ok11 = mcfix_patchVtableSlot(kSyncSlot, (void *)mcfix_syncSystemNoOp);

    // Layer 13a: queryAllAssetsForProvider no-op.
    // sub_100CA9838 (vtable 0x10154C698) is called when any world is opened.
    // It issues a CKQueryOperation via sub_100CA0E9C → sub_100C9F6C0.
    // If this query runs and completes with an error, the error handler
    // (sub_100CA48C4) dispatches status=7 to the main thread, which triggers
    // the "failed to sync world data" UI and flips the world into cloud-write
    // mode (changes go to an upload buffer, never flushed to disk on exit).
    // No-oping this vtable slot prevents the query from ever being queued:
    //   - Sync error dialog is never shown.
    //   - World opens in normal local-write mode: every save goes to disk.
    //   - Second (and subsequent) session changes persist correctly.
    BOOL ok13a = mcfix_patchVtableSlot(kNoQuerySlot, (void *)mcfix_syncSystemNoOp);

    // Layer 13b: remove-all-assets queue no-op.
    // sub_100CA9074 (vtable 0x10154C5C8) queues two "remove all assets"
    // actions (via sub_100CA1138 → sub_100C9F6C0) when the sync state machine
    // decides to wipe local files and re-download from cloud.  Each action
    // eventually reaches sub_100CA551C which drives the POSIX remove/rmdir
    // calls that delete the world directory.  The POSIX-level anti-wipe
    // (Layer 12) already blocks these at the syscall boundary; this patch
    // prevents them from being queued at all, eliminating state-machine
    // side-effects (e.g. a "wipe-complete" flag that would put the world
    // into a broken read-only re-download state on the next launch).
    BOOL ok13b = mcfix_patchVtableSlot(kNoWipeQueueSlot, (void *)mcfix_syncSystemNoOp);

    (void)ok1; (void)ok2; (void)ok3; (void)ok7; (void)ok8; (void)ok9;
    (void)ok11; (void)ok13a; (void)ok13b;
}

// ---------------------------------------------------------------------------
#pragma mark - Layer 6a — Library/games + Documents/games → Caches/.../GameData/vfs
// ---------------------------------------------------------------------------

+ (void)patchNSFileManagerLibraryGamesPathRedirect {
    Class c = [NSFileManager class];
    void (^swap)(SEL, SEL) = ^(SEL a, SEL b) {
        Method o = class_getInstanceMethod(c, a);
        Method t = class_getInstanceMethod(c, b);
        if (o && t) {
            method_exchangeImplementations(o, t);
        }
    };
    swap(@selector(createDirectoryAtPath:withIntermediateDirectories:attributes:error:), @selector(mcfix_games_createDirectoryAtPath:withIntermediateDirectories:attributes:error:));
    swap(@selector(createDirectoryAtURL:withIntermediateDirectories:attributes:error:), @selector(mcfix_games_createDirectoryAtURL:withIntermediateDirectories:attributes:error:));
    swap(@selector(fileExistsAtPath:), @selector(mcfix_games_fileExistsAtPath:));
    swap(@selector(fileExistsAtPath:isDirectory:), @selector(mcfix_games_fileExistsAtPath:isDirectory:));
    swap(@selector(copyItemAtPath:toPath:error:), @selector(mcfix_games_copyItemAtPath:toPath:error:));
    swap(@selector(moveItemAtPath:toPath:error:), @selector(mcfix_games_moveItemAtPath:toPath:error:));
    swap(@selector(removeItemAtPath:error:), @selector(mcfix_games_removeItemAtPath:error:));
    swap(@selector(contentsOfDirectoryAtPath:error:), @selector(mcfix_games_contentsOfDirectoryAtPath:error:));
    swap(@selector(subpathsOfDirectoryAtPath:error:), @selector(mcfix_games_subpathsOfDirectoryAtPath:error:));
    swap(@selector(attributesOfItemAtPath:error:), @selector(mcfix_games_attributesOfItemAtPath:error:));
    swap(@selector(createFileAtPath:contents:attributes:), @selector(mcfix_games_createFileAtPath:contents:attributes:));
    swap(@selector(enumeratorAtPath:), @selector(mcfix_games_enumeratorAtPath:));
    swap(@selector(isReadableFileAtPath:), @selector(mcfix_games_isReadableFileAtPath:));
    swap(@selector(isWritableFileAtPath:), @selector(mcfix_games_isWritableFileAtPath:));
    swap(@selector(copyItemAtURL:toURL:error:), @selector(mcfix_games_copyItemAtURL:toURL:error:));
    swap(@selector(moveItemAtURL:toURL:error:), @selector(mcfix_games_moveItemAtURL:toURL:error:));
    swap(@selector(removeItemAtURL:error:), @selector(mcfix_games_removeItemAtURL:error:));
    // Belt-and-suspenders: URL-based directory listing may bypass opendir hook on some
    // NSFileManager codepaths. Swizzle both variants so world discovery always sees Caches.
    swap(@selector(contentsOfDirectoryAtURL:includingPropertiesForKeys:options:error:),
         @selector(mcfix_games_contentsOfDirectoryAtURL:includingPropertiesForKeys:options:error:));
    swap(@selector(enumeratorAtURL:includingPropertiesForKeys:options:errorHandler:),
         @selector(mcfix_games_enumeratorAtURL:includingPropertiesForKeys:options:errorHandler:));
}

// ---------------------------------------------------------------------------
#pragma mark - Layer 6 — NSFileManager URLForUbiquityContainerIdentifier:
// ---------------------------------------------------------------------------

+ (void)patchNSFileManagerStorage {
    // Patch containerURLForSecurityApplicationGroupIdentifier:
    Method orig = class_getInstanceMethod([NSFileManager class],
        @selector(containerURLForSecurityApplicationGroupIdentifier:));
    Method swiz = class_getInstanceMethod(self,
        @selector(mcfix_containerURLForSecurityApplicationGroupIdentifier:));
    if (orig && swiz) {
        method_exchangeImplementations(orig, swiz);
    }

    // Patch URLForUbiquityContainerIdentifier: — prevents tvOS system
    // "Sign in to iCloud" sheet when the game requests an iCloud container.
    Method origUbiq = class_getInstanceMethod([NSFileManager class],
        @selector(URLForUbiquityContainerIdentifier:));
    Method swizUbiq = class_getInstanceMethod(self,
        @selector(mcfix_URLForUbiquityContainerIdentifier:));
    if (origUbiq && swizUbiq) {
        method_exchangeImplementations(origUbiq, swizUbiq);
    }
}

// Redirects app-group containers to a writable Caches path; avoids EPERM on
// physical Apple TV hardware where the real shared container is entitlement-gated.
- (NSURL *)mcfix_containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    if (!groupIdentifier.length) {
        groupIdentifier = @"unknown";
    }

    NSString *home     = NSHomeDirectory();
    NSString *basePath = [home stringByAppendingPathComponent:
                          @"Library/Caches/AppGroupContainers"];
    NSURL *containerURL = [[NSURL fileURLWithPath:basePath isDirectory:YES]
                            URLByAppendingPathComponent:groupIdentifier];

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:containerURL.path]) {
        for (NSString *sub in @[@"Library", @"Library/Application Support",
                                @"Library/Caches", @"Library/Preferences",
                                @"Documents", @"tmp"]) {
            [fm createDirectoryAtURL:[containerURL URLByAppendingPathComponent:sub]
         withIntermediateDirectories:YES
                          attributes:nil
                               error:nil];
        }
        [containerURL setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    }

    return containerURL;
}

// Returns a local directory URL instead of a real iCloud container URL.
// Prevents the OS-level "Sign in to iCloud" sheet on tvOS when the game
// (or a linked framework) requests a ubiquity container.
- (NSURL *)mcfix_URLForUbiquityContainerIdentifier:(NSString *)containerIdentifier {
    NSString *home = NSHomeDirectory();
    NSString *base = [home stringByAppendingPathComponent:
                      @"Library/Caches/iCloudContainerSim"];

    if (containerIdentifier.length) {
        NSString *sanitized = [containerIdentifier
                               stringByReplacingOccurrencesOfString:@"." withString:@"_"];
        base = [base stringByAppendingPathComponent:sanitized];
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:base]) {
        [fm createDirectoryAtPath:base
     withIntermediateDirectories:YES
                      attributes:nil
                           error:nil];
    }

    return [NSURL fileURLWithPath:base isDirectory:YES];
}

// ---------------------------------------------------------------------------
#pragma mark - NSFileManager — Ubiquity Token (Layer 1)
// ---------------------------------------------------------------------------

+ (void)patchNSFileManagerUbiquity {
    Method origToken = class_getInstanceMethod([NSFileManager class],
        @selector(ubiquityIdentityToken));
    Method swizToken = class_getInstanceMethod(self,
        @selector(mcfix_ubiquityIdentityToken));
    if (origToken && swizToken) {
        method_exchangeImplementations(origToken, swizToken);
    }
}

// Always returns nil.  Minecraft stores the previous token under NSUserDefaults
// key "com.mojang.minecraftappletv.UbiquityIdentityToken".  nil == nil means
// "no change", so the CloudKit re-init path that dereferences the null Impl*
// is skipped.
- (id)mcfix_ubiquityIdentityToken {
    return nil;
}

// ---------------------------------------------------------------------------
#pragma mark - CloudKit — defaultContainer wrapper (Layer 3)
// ---------------------------------------------------------------------------

+ (void)patchCloudKit {
    Class ckClass = objc_getClass("CKContainer");
    if (!ckClass) return;

    // Nil stub — see NOTE (Layer 3) before MCFIXMinecraftMainBundleId.
    Method origDefault = class_getClassMethod(ckClass, @selector(defaultContainer));
    Method swizDefault = class_getClassMethod(self, @selector(mcfix_defaultContainer));
    if (origDefault && swizDefault) {
        method_exchangeImplementations(origDefault, swizDefault);
    }
}

+ (id)mcfix_defaultContainer {
    return nil;
}

// ---------------------------------------------------------------------------
#pragma mark - iCloudNotificationListener — surgical no-op (Layer 2)
// ---------------------------------------------------------------------------

// iCloudAccountAvailabilityChanged: (0x100c9ed90) is registered for BOTH:
//   • NSUbiquityIdentityDidChangeNotification
//   • CKAccountChangedNotification
// Both fire on sideloaded builds immediately after launch; the implementation
// calls [CKContainer defaultContainer] → fetchUserRecordIDWithCompletionHandler:
// whose block dereferences the null iCloudStorage::Impl* → crash.
// Replacing the method with a no-op blocks both notification paths.
+ (void)patchICloudNotificationListener {
    Class listenerClass = objc_getClass("iCloudNotificationListener");
    if (!listenerClass) return;

    Method orig = class_getInstanceMethod(listenerClass,
        @selector(iCloudAccountAvailabilityChanged:));
    Method swiz = class_getInstanceMethod(self,
        @selector(mcfix_iCloudAccountAvailabilityChanged:));
    if (orig && swiz) {
        method_exchangeImplementations(orig, swiz);
    }
}

- (void)mcfix_iCloudAccountAvailabilityChanged:(id)notification {
    // Intentional no-op.
}

// ---------------------------------------------------------------------------
#pragma mark - Game Data Directories (Layer 4)
// ---------------------------------------------------------------------------

// Path list aligned with sub_10069216C / sub_1006E64E0 string join (Layer 6a).
// Also covers the framework-only runtime roots (tmp/Temp/games, tmp/Temp/internal)
// which are the real write destinations when sub_1006E64E0 is not hooked.
// createDirectory calls go through the swizzle → land in .../vfs/<tail> (persistent).
+ (void)ensureGameDataDirectories {
    NSFileManager *fm   = [NSFileManager defaultManager];
    NSString      *home = NSHomeDirectory();

    NSArray<NSString *> *paths = @[
        [home stringByAppendingPathComponent:@"Library/games/com.mojang"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/minecraftWorlds"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/minecraftStructures"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/resource_packs"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/behavior_packs"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/skin_packs"],
        [home stringByAppendingPathComponent:@"Library/games/com.mojang/screenshots"],
        [home stringByAppendingPathComponent:@"Documents/games/com.mojang"],
        [home stringByAppendingPathComponent:@"Documents/games/com.mojang/minecraftWorlds"],
        // Framework-only roots: game writes here when sub_1006E64E0 is not hooked.
        // The swizzle redirects these to the persistent Caches vfs tree.
        [home stringByAppendingPathComponent:@"tmp/Temp/games/com.mojang"],
        [home stringByAppendingPathComponent:@"tmp/Temp/games/com.mojang/minecraftWorlds"],
        [home stringByAppendingPathComponent:@"tmp/Temp/internal"],
        // Secondary content root (IDA: sub_100792D10, a1+312 = NSTemporaryDirectory()+"/minecraftpe").
        // Uses raw NSTemporaryDirectory() (no /Temp), tail = "tmp/minecraftpe".
        // Stores packs, screenshots, and secondary game content.
        [home stringByAppendingPathComponent:@"tmp/minecraftpe"],
        [home stringByAppendingPathComponent:@"tmp/minecraftpe/games/com.mojang"],
        [home stringByAppendingPathComponent:@"tmp/minecraftpe/games/com.mojang/minecraftWorlds"],
    ];

    for (NSString *path in paths) {
        if (![fm fileExistsAtPath:path]) {
            [fm createDirectoryAtPath:path
          withIntermediateDirectories:YES
                           attributes:nil
                                error:nil];
        }
        NSString *markPath = MCFIXPathByRedirectingGameStorage(path);
        if (markPath.length) {
            [[NSURL fileURLWithPath:markPath] setResourceValue:@YES
                                                        forKey:NSURLIsExcludedFromBackupKey
                                                         error:nil];
        }
    }
}

// ---------------------------------------------------------------------------
#pragma mark - Ubiquity Notification Guard (Layer 1 supplement)
// ---------------------------------------------------------------------------

// Clears the stored ubiquity token from NSUserDefaults if the notification
// fires before the swizzle is in effect. nil == nil → "no change" → iCloud
// re-init path skipped.
+ (void)installUbiquityNotificationGuard {
    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"NSUbiquityIdentityDidChangeNotification"
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *note) {
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        [ud removeObjectForKey:@"com.mojang.minecraftappletv.UbiquityIdentityToken"];
        [ud synchronize];
    }];
}

@end

@implementation NSFileManager (MinecraftStorageFix_LibraryGames)

- (BOOL)mcfix_games_createDirectoryAtPath:(NSString *)path
              withIntermediateDirectories:(BOOL)createIntermediates
                               attributes:(NSDictionary *)attributes
                                    error:(NSError **)error {
    NSString *n = MCFIXPathByRedirectingGameStorage(path);
    return [self mcfix_games_createDirectoryAtPath:n
                       withIntermediateDirectories:createIntermediates
                                        attributes:attributes
                                             error:error];
}

- (BOOL)mcfix_games_createDirectoryAtURL:(NSURL *)url
              withIntermediateDirectories:(BOOL)createIntermediates
                               attributes:(NSDictionary *)attributes
                                    error:(NSError **)error {
    if (![url isFileURL]) {
        return [self mcfix_games_createDirectoryAtURL:url
                        withIntermediateDirectories:createIntermediates
                                         attributes:attributes
                                              error:error];
    }
    return [self mcfix_games_createDirectoryAtURL:MCFIXFileURLByRedirectingGameStorage(url)
                        withIntermediateDirectories:createIntermediates
                                         attributes:attributes
                                              error:error];
}

- (BOOL)mcfix_games_fileExistsAtPath:(NSString *)path {
    return [self mcfix_games_fileExistsAtPath:MCFIXPathByRedirectingGameStorage(path)];
}

- (BOOL)mcfix_games_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    return [self mcfix_games_fileExistsAtPath:MCFIXPathByRedirectingGameStorage(path) isDirectory:isDir];
}

- (BOOL)mcfix_games_copyItemAtPath:(NSString *)s toPath:(NSString *)d error:(NSError **)e {
    return [self mcfix_games_copyItemAtPath:MCFIXPathByRedirectingGameStorage(s) toPath:MCFIXPathByRedirectingGameStorage(d) error:e];
}

- (BOOL)mcfix_games_moveItemAtPath:(NSString *)s toPath:(NSString *)d error:(NSError **)e {
    return [self mcfix_games_moveItemAtPath:MCFIXPathByRedirectingGameStorage(s) toPath:MCFIXPathByRedirectingGameStorage(d) error:e];
}

- (BOOL)mcfix_games_removeItemAtPath:(NSString *)path error:(NSError **)e {
    return [self mcfix_games_removeItemAtPath:MCFIXPathByRedirectingGameStorage(path) error:e];
}

- (NSArray *)mcfix_games_contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)e {
    return [self mcfix_games_contentsOfDirectoryAtPath:MCFIXPathByRedirectingGameStorage(path) error:e];
}

- (NSArray *)mcfix_games_subpathsOfDirectoryAtPath:(NSString *)path error:(NSError **)e {
    return [self mcfix_games_subpathsOfDirectoryAtPath:MCFIXPathByRedirectingGameStorage(path) error:e];
}

- (NSDictionary *)mcfix_games_attributesOfItemAtPath:(NSString *)path error:(NSError **)e {
    return [self mcfix_games_attributesOfItemAtPath:MCFIXPathByRedirectingGameStorage(path) error:e];
}

- (BOOL)mcfix_games_createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    return [self mcfix_games_createFileAtPath:MCFIXPathByRedirectingGameStorage(path) contents:data attributes:attr];
}

- (NSEnumerator *)mcfix_games_enumeratorAtPath:(NSString *)path {
    return [self mcfix_games_enumeratorAtPath:MCFIXPathByRedirectingGameStorage(path)];
}

- (BOOL)mcfix_games_isReadableFileAtPath:(NSString *)path {
    return [self mcfix_games_isReadableFileAtPath:MCFIXPathByRedirectingGameStorage(path)];
}

- (BOOL)mcfix_games_isWritableFileAtPath:(NSString *)path {
    return [self mcfix_games_isWritableFileAtPath:MCFIXPathByRedirectingGameStorage(path)];
}

- (BOOL)mcfix_games_copyItemAtURL:(NSURL *)s toURL:(NSURL *)d error:(NSError **)e {
    NSURL *s2 = [s isFileURL] ? MCFIXFileURLByRedirectingGameStorage(s) : s;
    NSURL *d2 = [d isFileURL] ? MCFIXFileURLByRedirectingGameStorage(d) : d;
    return [self mcfix_games_copyItemAtURL:s2 toURL:d2 error:e];
}

- (BOOL)mcfix_games_moveItemAtURL:(NSURL *)s toURL:(NSURL *)d error:(NSError **)e {
    NSURL *s2 = [s isFileURL] ? MCFIXFileURLByRedirectingGameStorage(s) : s;
    NSURL *d2 = [d isFileURL] ? MCFIXFileURLByRedirectingGameStorage(d) : d;
    return [self mcfix_games_moveItemAtURL:s2 toURL:d2 error:e];
}

- (BOOL)mcfix_games_removeItemAtURL:(NSURL *)u error:(NSError **)e {
    if (![u isFileURL]) {
        return [self mcfix_games_removeItemAtURL:u error:e];
    }
    return [self mcfix_games_removeItemAtURL:MCFIXFileURLByRedirectingGameStorage(u) error:e];
}

- (NSArray *)mcfix_games_contentsOfDirectoryAtURL:(NSURL *)url
                       includingPropertiesForKeys:(NSArray *)keys
                                         options:(NSDirectoryEnumerationOptions)mask
                                           error:(NSError **)e {
    NSURL *u2 = ([url isFileURL]) ? MCFIXFileURLByRedirectingGameStorage(url) : url;
    return [self mcfix_games_contentsOfDirectoryAtURL:u2
                           includingPropertiesForKeys:keys
                                             options:mask
                                               error:e];
}

- (NSDirectoryEnumerator *)mcfix_games_enumeratorAtURL:(NSURL *)url
                            includingPropertiesForKeys:(NSArray *)keys
                                              options:(NSDirectoryEnumerationOptions)mask
                                         errorHandler:(BOOL (^)(NSURL *, NSError *))handler {
    NSURL *u2 = ([url isFileURL]) ? MCFIXFileURLByRedirectingGameStorage(url) : url;
    return [self mcfix_games_enumeratorAtURL:u2
                  includingPropertiesForKeys:keys
                                    options:mask
                                errorHandler:handler];
}

@end
