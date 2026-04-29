//
//  MinecraftStorageFix.h
//  MinecraftStorageFix
//
//  Public framework header for MinecraftStorageFix.
//  Embed this framework inside Minecraft for Apple TV to fix iCloud,
//  CloudKit, and storage crashes on sideloaded (non-entitlement) builds.
//
//  No configuration required — all patches are applied automatically
//  via +[MinecraftStorageFix load] when the framework is first mapped.
//

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT double MinecraftStorageFixVersionNumber;
FOUNDATION_EXPORT const unsigned char MinecraftStorageFixVersionString[];
