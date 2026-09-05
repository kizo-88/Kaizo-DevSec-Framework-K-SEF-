#!/usr/bin/env bash
# ==============================================================================
# Kaizo DevSec Framework - Subresource Integrity (SRI) Hash Generator
# Mitigates: CWE-345 (Sub Resource Integrity Attribute Missing)
# ==============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: ./sri-generator.sh <URL_OR_FILE_PATH>"
    echo "Example: ./sri-generator.sh https://cdnjs.cloudflare.com/ajax/libs/axios/1.6.8/axios.min.js"
    echo "Example: ./sri-generator.sh ./public/vendor/script.js"
    exit 1
fi

TARGET="$1"

echo "--------------------------------------------------------"
echo "🔐 Generating Subresource Integrity (SRI) Hash for:"
echo "   $TARGET"
echo "--------------------------------------------------------"

if [[ "$TARGET" =~ ^https?:// ]]; then
    # Remote URL
    HASH=$(curl -sSL "$TARGET" | openssl dgst -sha384 -binary | openssl base64 -A)
    TAG_TYPE="script"
    if [[ "$TARGET" =~ \.css$ ]]; then
        TAG_TYPE="link"
    fi
else
    # Local File
    if [ ! -f "$TARGET" ]; then
        echo "❌ Error: File '$TARGET' not found."
        exit 1
    fi
    HASH=$(openssl dgst -sha384 -binary < "$TARGET" | openssl base64 -A)
    TAG_TYPE="script"
    if [[ "$TARGET" =~ \.css$ ]]; then
        TAG_TYPE="link"
    fi
fi

INTEGRITY="sha384-$HASH"

echo ""
echo "✅ SRI Hash: $INTEGRITY"
echo ""
echo "📋 Ready-to-use HTML Snippet:"
if [ "$TAG_TYPE" == "script" ]; then
    echo "<script src=\"$TARGET\" integrity=\"$INTEGRITY\" crossorigin=\"anonymous\" referrerpolicy=\"no-referrer\"></script>"
else
    echo "<link rel=\"stylesheet\" href=\"$TARGET\" integrity=\"$INTEGRITY\" crossorigin=\"anonymous\" referrerpolicy=\"no-referrer\">"
fi
echo "--------------------------------------------------------"
