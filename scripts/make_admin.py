import asyncio
import argparse
from sqlalchemy import select
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import User

async def make_admin(email: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            print(f"❌ User with email '{email}' not found.")
            return

        user.role = "admin"
        await session.commit()
        print(f"✅ Success! User '{email}' is now an Admin.")
        print("You may need to log out and log back in for the changes to take effect in the UI.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Promote a user to Admin")
    parser.add_argument("email", help="The email address of the user to promote")
    args = parser.parse_args()

    asyncio.run(make_admin(args.email))
