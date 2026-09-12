# Piper Local TTS Licensing

JARVIS can use `piper-tts==1.7.0` as an optional, separately installed local
speech provider for private development. Piper is third-party software licensed
under GPL-3.0-or-later; it is not proprietary JARVIS code and is not bundled by
the base package.

Piper remains behind the `TtsProvider` boundary. A local voice model must be
selected explicitly, and synthesis does not require network access. Any
commercial distribution involving Piper requires separate legal and compliance
review before release.