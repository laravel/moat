# This repo doubles as a Homebrew tap. Users install with:
#   brew install laravel/moat/moat
#
# This file is updated automatically by the release workflow.

class Moat < Formula
  desc "security posture auditing for your github organization & repositories"
  homepage "https://github.com/laravel/moat"
  version "1.0.7"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "1401c684df2abdc4818d805684e163d69b9edf49c7acd4e5ce474fd70434e324"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d189a5c2dd19d3215d0ce94d27185eb06e8d67262839e8767d6631377f05d557"
    end
    on_intel do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "835aae3644a1f756466db4608d6cac87c691444fb743d02808276a09b9dc8a75"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
