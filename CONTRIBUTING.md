# Contributing to DDoS Guard

Thank you for considering contributing to DDoS Guard!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Code Style

- Use shellcheck to validate bash scripts
- Follow existing code style
- Add comments for complex logic
- Update README.md if adding features

## Testing

Before submitting:
- Test on a non-production system
- Verify systemd service starts correctly
- Check logs for errors
- Test with actual SYN flood (use hping3 carefully)

## Questions?

Open an issue for discussion before major changes.

