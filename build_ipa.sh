#!/bin/bash
set -euo pipefail

rm -rf build
mkdir -p build

echo "🚀 Build Started"
echo

# билд без archive (важно!)
xcodebuild \
  -project lara.xcodeproj \
  -scheme lara \
  -configuration Debug \
  -sdk iphoneos \
  -destination "generic/platform=iOS" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  build | tee build/xcodebuild.log

# ищем .app
APP_PATH=$(find "$PWD/build" -name "lara.app" -type d | head -n 1)

if [ -z "$APP_PATH" ]; then
  echo "❌ .app NOT FOUND"
  exit 1
fi

echo "✅ Found app at: $APP_PATH"

# собираем IPA
rm -rf build/Payload
mkdir -p build/Payload
cp -R "$APP_PATH" build/Payload/

# plist фикс
plutil -replace UIFileSharingEnabled -bool YES build/Payload/lara.app/Info.plist || true

# проверка ldid
if ! command -v ldid >/dev/null 2>&1; then
  echo "❌ ldid not installed"
  exit 1
fi

# подпись
ldid -SConfig/lara.entitlements build/Payload/lara.app/lara || true

# упаковка
cd build
zip -qry lara.ipa Payload

echo
echo "✅ BUILD SUCCESS"
echo "📦 IPA: build/lara.ipa"
