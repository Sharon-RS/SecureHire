"""Local-only development entry point."""

from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app()


if __name__ == "__main__":
    # Keep the development server bound to loopback; never use 0.0.0.0.
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
