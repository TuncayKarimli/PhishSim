"""Per-employee and per-group (Department / Location / Business Unit) risk view."""
from flask import Blueprint, render_template, request
from flask_login import login_required

from ..models import Target

bp = Blueprint("people", __name__)


def _band(score: float) -> str:
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


def _aggregate_group(rows: list[dict], key: str) -> list[dict]:
    """Aggregate employee risk metrics by department, location, or business_unit."""
    groups: dict[str, dict] = {}
    for p in rows:
        label = (p.get(key) or "").strip() or "Unassigned"
        g = groups.setdefault(
            label,
            {
                "name": label,
                "people_count": 0,
                "targeted": 0,
                "opened": 0,
                "clicked": 0,
                "submitted": 0,
                "reported": 0,
                "total_score": 0,
            },
        )
        g["people_count"] += 1
        g["targeted"] += p["targeted"]
        g["opened"] += p["opened"]
        g["clicked"] += p["clicked"]
        g["submitted"] += p["submitted"]
        g["reported"] += p["reported"]
        g["total_score"] += p["score"]

    result = []
    for g in groups.values():
        cnt = g["people_count"] or 1
        avg_score = round(g["total_score"] / cnt, 1)
        g["avg_score"] = avg_score
        g["band"] = _band(avg_score)
        g["compromise_rate"] = round((g["submitted"] / g["targeted"]) * 100, 1) if g["targeted"] else 0.0
        result.append(g)

    result.sort(key=lambda x: (-x["avg_score"], -x["submitted"], -x["clicked"]))
    return result


@bp.route("/people")
@login_required
def index():
    people: dict[str, dict] = {}
    for t in Target.query.all():
        p = people.setdefault(
            t.email,
            {
                "email": t.email,
                "name": t.full_name,
                "department": t.department or "",
                "location": t.location or "",
                "business_unit": t.business_unit or "",
                "targeted": 0,
                "opened": 0,
                "clicked": 0,
                "submitted": 0,
                "reported": 0,
            },
        )
        p["targeted"] += 1
        if t.full_name != t.email:
            p["name"] = t.full_name
        if t.department:
            p["department"] = t.department
        if t.location:
            p["location"] = t.location
        if t.business_unit:
            p["business_unit"] = t.business_unit

        types = t.types
        for stage in ("opened", "clicked", "submitted"):
            if stage in types:
                p[stage] += 1
        if t.reported:
            p["reported"] += 1

    all_rows = list(people.values())
    for p in all_rows:
        p["score"] = max(0, p["submitted"] * 3 + p["clicked"] * 1 - p["reported"] * 1)
        p["band"] = _band(p["score"])
    all_rows.sort(key=lambda p: (-p["score"], -p["submitted"], -p["clicked"]))

    departments = sorted({r["department"] for r in all_rows if r["department"]})
    locations = sorted({r["location"] for r in all_rows if r["location"]})
    business_units = sorted({r["business_unit"] for r in all_rows if r["business_unit"]})

    # Optional server-side query filters in addition to instant client-side filtering
    sel_dept = request.args.get("department", "").strip()
    sel_loc = request.args.get("location", "").strip()
    sel_bu = request.args.get("business_unit", "").strip()

    filtered_rows = [
        r
        for r in all_rows
        if (not sel_dept or r["department"] == sel_dept)
        and (not sel_loc or r["location"] == sel_loc)
        and (not sel_bu or r["business_unit"] == sel_bu)
    ]

    dept_summary = _aggregate_group(all_rows, "department")
    loc_summary = _aggregate_group(all_rows, "location")
    bu_summary = _aggregate_group(all_rows, "business_unit")

    return render_template(
        "people.html",
        rows=filtered_rows,
        departments=departments,
        locations=locations,
        business_units=business_units,
        sel_dept=sel_dept,
        sel_loc=sel_loc,
        sel_bu=sel_bu,
        dept_summary=dept_summary,
        loc_summary=loc_summary,
        bu_summary=bu_summary,
    )
