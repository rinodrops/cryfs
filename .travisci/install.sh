#!/bin/bash

set -e

export HOMEBREW_NO_AUTO_UPDATE=1

# Needed for GCC 9 to work, see https://github.com/trinityrnaseq/trinityrnaseq/issues/599
# TODO Still needed?
softwareupdate --install "Command Line Tools (macOS High Sierra version 10.13) for Xcode-10.1"


# Install newer GCC if we're running on GCC
if [ "${CXX}" == "g++-9" ]; then
    brew install gcc@9
    conan profile update settings.compiler.libcxx=libstdc++ default
fi

brew cask install osxfuse
brew install libomp

# By default, travis only fetches the newest 50 commits. We need more in case we're further from the last version tag, so the build doesn't fail because it can't generate the version number.
git fetch --unshallow --tags

pip install conan

# Setup ccache
brew install ccache
