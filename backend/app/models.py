import uuid
from sqlalchemy import Boolean, ForeignKey, String, Uuid, false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)

class TenantModule(Base):
    __tablename__ = "tenant_modules"
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), primary_key=True)
    module_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
