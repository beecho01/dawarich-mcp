"""Pydantic output models for tool results.

Structured output keeps results machine-checkable and lets the sanitisation
layer validate every field against a known shape before it reaches a model.
Location history is personal data: these models deliberately carry the
minimum fields each tool actually needs, never raw upstream payloads.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class TrackedYear(BaseModel):
    year: int
    months: list[str]


class StatusReport(BaseModel):
    dawarich_healthy: bool
    api_key_valid: bool
    user_email: str | None = None
    timezone: str | None = None
    distance_unit: str | None = None
    tracked_months: list[TrackedYear] = Field(default_factory=list)
    note: str


class PointLocation(BaseModel):
    timestamp: str
    latitude: float
    longitude: float
    altitude_m: float | None = None
    accuracy_m: float | None = None
    velocity_kmh: float | None = None
    city: str | None = None
    country: str | None = None
    tracker_id: str | None = None


class LatestLocation(BaseModel):
    point: PointLocation | None
    note: str


class VisitEntry(BaseModel):
    started_at: str | None = None
    ended_at: str | None = None
    name: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    city: str | None = None
    country: str | None = None
    duration_minutes: float | None = None
    status: str | None = None


class VisitsReport(BaseModel):
    start_at: str
    end_at: str
    total_returned: int
    visits: list[VisitEntry]
    note: str


class MonthlyDistance(BaseModel):
    month: str
    distance_km: float


class YearDistance(BaseModel):
    year: int
    total_distance_km: float
    countries_visited: int = 0
    cities_visited: int = 0
    monthly: list[MonthlyDistance] = Field(default_factory=list)


class StatsReport(BaseModel):
    total_distance_km: float
    total_points_tracked: int
    years: list[YearDistance]
    note: str


class YearInsights(BaseModel):
    year: int
    available_years: list[int]
    total_distance: float
    distance_unit: str
    countries_count: int
    cities_count: int
    days_traveling: int
    biggest_month: str | None = None
    note: str


class DigestReport(BaseModel):
    year: int
    distance_m: float | None = None
    countries_count: int | None = None
    cities_count: int | None = None
    created_at: str | None = None
    note: str


class GeofenceEventEntry(BaseModel):
    occurred_at: str | None = None
    place_id: str | None = None
    place_name: str | None = None
    direction: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class GeofenceEventsReport(BaseModel):
    start_at: str
    end_at: str
    total_returned: int
    events: list[GeofenceEventEntry]
    note: str


class VisitedPlacesReport(BaseModel):
    start_at: str
    end_at: str
    countries: list[str] = Field(default_factory=list)
    cities: list[str] = Field(default_factory=list)
    note: str
