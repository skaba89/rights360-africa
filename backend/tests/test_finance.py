"""Unit tests for the PHASE 4 finance/SYSCOHADA module (no database required).

Run by the ``api`` CI job alongside the other ``test_*.py`` files. These cover
the pure logic and auth-gating of the new endpoints; the behavioral flow
(chart seed, reversal netting, multi-level close, beneficiary statement) is
exercised against a real database by ``finance_integration.py`` in the
``docker`` CI job.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.finance import (
    ChartAccountData, AccountMappingData, JournalData, FiscalPeriodData,
    FiscalReviewData, TaxRuleData, DEFAULT_CHART, DEFAULT_MAPPINGS,
)


def test_chart_account_validation():
    a = ChartAccountData(account_code="411000", name="Clients", syscohada_class="4", account_type="asset")
    assert a.is_postable is True
    with pytest.raises(ValueError):
        ChartAccountData(account_code="411000", name="x", syscohada_class="9", account_type="asset")  # bad class
    with pytest.raises(ValueError):
        ChartAccountData(account_code="ABC", name="x", syscohada_class="4", account_type="asset")  # non-digit code
    with pytest.raises(ValueError):
        ChartAccountData(account_code="411000", name="x", syscohada_class="4", account_type="cash")  # bad type
    with pytest.raises(ValueError):
        ChartAccountData(account_code="123456789", name="x", syscohada_class="4", account_type="asset")  # >8 digits


def test_account_mapping_keys_are_closed():
    # The bridge only accepts the five generic keys accounting.py hardcodes.
    valid = {"receivable", "royalties_unallocated", "cash_unverified",
             "management_commission", "beneficiary_payable"}
    assert set(DEFAULT_MAPPINGS.keys()) == valid
    with pytest.raises(ValueError):
        AccountMappingData(generic_key="unknown", account_code="411000")


def test_journal_validation():
    j = JournalData(code="VTE", name="Ventes", kind="sales")
    assert j.kind == "sales"
    for bad in ("", "ventes!", "VENTESVENTESVENTES"):  # empty, non-alnum, too long
        with pytest.raises(ValueError):
            JournalData(code=bad, name="x", kind="sales")
    with pytest.raises(ValueError):
        JournalData(code="VTE", name="x", kind="treasury")  # bad kind


def test_fiscal_period_validation():
    p = FiscalPeriodData(fiscal_year=2026, period_index=0, starts_on="2026-01-01", ends_on="2026-12-31")
    assert p.period_index == 0
    with pytest.raises(ValueError):
        FiscalPeriodData(fiscal_year=2026, period_index=13, starts_on="2026-01-01", ends_on="2026-12-31")
    with pytest.raises(ValueError):
        FiscalPeriodData(fiscal_year=2026, period_index=0, starts_on="2026-12-31", ends_on="2026-01-01")  # ends<starts


def test_fiscal_review_decision_closed():
    assert FiscalReviewData(decision="approve").decision == "approve"
    with pytest.raises(ValueError):
        FiscalReviewData(decision="maybe")


def test_tax_rule_validation():
    t = TaxRuleData(category="performance", country="CI", rate_bps=2000)
    assert t.rate_bps == 2000
    with pytest.raises(ValueError):
        TaxRuleData(category="performance", country="CIV", rate_bps=2000)  # not 2 letters
    with pytest.raises(ValueError):
        TaxRuleData(category="performance", country="ci", rate_bps=2000)  # lowercase
    with pytest.raises(ValueError):
        TaxRuleData(category="performance", country="CI", rate_bps=20000)  # > 10000 (100%)


def test_default_chart_is_self_consistent():
    # Every default mapping account_code must exist in the default chart.
    chart_codes = {code for code, _, _, _ in DEFAULT_CHART}
    for acct in DEFAULT_MAPPINGS.values():
        assert acct in chart_codes, f"default mapping targets unknown account {acct}"
    # Classes are valid SYSCOHADA classes 1-8.
    for _, _, cls, _ in DEFAULT_CHART:
        assert cls in {"1", "2", "3", "4", "5", "6", "7", "8"}


def test_finance_routes_require_auth():
    # Every read endpoint must reject an unauthenticated request with 401.
    for path in ("/api/v1/finance/chart-of-accounts", "/api/v1/finance/trial-balance",
                 "/api/v1/finance/general-ledger", "/api/v1/finance/fiscal-periods"):
        assert TestClient(app).get(path).status_code == 401, path
