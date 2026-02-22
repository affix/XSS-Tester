"""
Models/Spider.py — Data types produced by the spider and consumed by the tester.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InputField:
    """A single testable HTML input field discovered on a page."""

    selector: str
    """CSS selector that uniquely (best-effort) identifies the element."""

    name: Optional[str]
    """Value of the ``name`` attribute, if present."""

    input_type: str
    """Normalised input type: ``text``, ``email``, ``textarea``, ``select``, etc."""

    form_selector: Optional[str]
    """CSS selector for the containing ``<form>``, or *None* if standalone."""

    form_action: Optional[str]
    """Resolved form action URL, or *None* if outside a form."""

    form_method: str
    """HTTP method of the containing form: ``GET`` or ``POST``."""


@dataclass
class UrlParam:
    """A URL query parameter discovered on a crawled page."""

    url: str
    """Full page URL containing the parameter."""

    param_name: str
    """Query parameter name."""

    original_value: str
    """Original value of the parameter."""


@dataclass
class PageData:
    """All testable data collected from a single crawled page."""

    url: str
    """Final URL after any redirects."""

    depth: int
    """Crawl depth at which this page was discovered."""

    inputs: list[InputField] = field(default_factory=list)
    """All testable input fields found on the page."""

    url_params: list[UrlParam] = field(default_factory=list)
    """URL parameters present on the page."""

    links: list[str] = field(default_factory=list)
    """In-scope outgoing links (used internally by the spider)."""
