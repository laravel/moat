# This repo doubles as a Homebrew tap. Users install with:
#   brew install laravel/moat/moat
#
# This file is updated automatically by the release workflow.

class Moat < Formula
  desc "security posture auditing for your github organization & repositories"
  homepage "https://github.com/laravel/moat"
  version "1.0.8"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "6c42a42eeca99e480393c6fc9739bbbf40871ef02b020006aee9e58553f4332f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e27109ffb0538cd73f36d5885418178aba92e90c137d7c1c535187b65f2499c0"
    end
    on_intel do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3ad5b451025b6c98b9a0ec8fbff23d8615c5a031b317607e6af78f8635a1eb0b"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
