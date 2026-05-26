# This repo doubles as a Homebrew tap. Users install with:
#   brew install laravel/moat/moat
#
# This file is updated automatically by the release workflow.

class Moat < Formula
  desc "security posture auditing for your github organization & repositories"
  homepage "https://github.com/laravel/moat"
  version "1.0.4"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "1944f7aa8033d16cd628ef26531fe5c547d7f8d1b2508b936595e5d22dd37e69"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "353e4162427f91d2a9272f39732a92d1752c11a8c82be7ab2a1f3916c2e81580"
    end
    on_intel do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "dc61680aa95ca5aef1e08ba8db163ed59e76bd39016fa07c55d9dd4af9467076"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
