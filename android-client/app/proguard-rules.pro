# ShadowTunnel ProGuard Rules

# Keep Bouncy Castle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep SnakeYAML
-keep class org.yaml.snakeyaml.** { *; }

# Keep ShadowTunnel protocol classes
-keep class com.shadowtunnel.protocol.** { *; }
-keep class com.shadowtunnel.vpn.** { *; }
