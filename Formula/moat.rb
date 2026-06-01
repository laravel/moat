# This repo doubles as a Homebrew tap. Users install with:
#   brew install laravel/moat/moat
#
# This file is updated automatically by the release workflow.

class Moat < Formula
  desc "security posture auditing for your github organization & repositories"
  homepage "https://github.com/laravel/moat"
  version "1.0.5"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "4da16d598ffe5135a8ed73f169fe134da97608d656c5f3d2e893ef8fb59c8cef"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1b0f043819adf9d8ffd62b2d3dbdd49c8dde1ea559221a82dc04d7f9c8a79cec"
    end
    on_intel do
      url "https://github.com/laravel/moat/releases/download/v#{version}/moat-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b6ffa9b08c1df6d2745c8e143b98ff7d97f2108f5f22d44e248d0b1c43734d0b"
    end
  end

  def install
    bin.install "moat"
  end

  test do
    assert_match "moat", shell_output("#{bin}/moat --help")
  end
end
