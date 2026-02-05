# RoomSync - Household Management App

Team 6 RoomSync is a web application designed to simplify household management. It features secure user authentication, group management, shared grocery lists, and receipt scanning powered by Google Document AI.

**[🚀 Live Demo](https://team6-roomsync.vercel.app)**

## Features
-   **Group Management**: Create or join household groups with unique codes.
-   **Authentication**: Secure login and registration.
-   **Groceries**: Shared list with real-time updates.
-   **Receipt Scanning**: Upload receipts to automatically parse items and prices using AI.

## Deployment (Vercel)

This project is deployed on [Vercel](https://vercel.com).

**Live URL**: `https://team6-roomsync.vercel.app`

### Environment Variables
For the application to function correctly, the following environment variables must be set in Vercel:
-   `SECRET_KEY`: Random string for session security.
-   `POSTGRES_URL`: Connection string for the Vercel Postgres database.
-   `ANTHROPIC_API_KEY`: API Key for Anthropic Claude (used for receipt scanning).

## Local Development

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/zkisaboss/Team6_RoomSync.git
    cd Team6_RoomSync
    ```

2.  **Set up Virtual Environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Configure `.env`**:
    Create a `.env` file in the root directory:
    ```bash
    SECRET_KEY=dev-key
    POSTGRES_URL=postgresql://user:password@host:port/database
    ANTHROPIC_API_KEY=your_key_here
    ```

4.  **Run the App**:
    ```bash
    python3 app.py
    ```
    Visit `http://127.0.0.1:5001`.