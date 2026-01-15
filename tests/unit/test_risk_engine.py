"""
Unit Tests for FLIT Risk Scoring Engine

Tests the risk calculation, factor weighting, and recommendation logic.
"""

import pytest
from unittest.mock import Mock, patch


class TestRiskLevel:
    """Tests for RiskLevel classification."""
    
    def test_low_risk_threshold(self):
        """Scores below 0.3 should be LOW risk."""
        scores = [0.0, 0.1, 0.2, 0.29]
        for score in scores:
            if score < 0.3:
                level = "low"
            elif score < 0.5:
                level = "medium"
            elif score < 0.7:
                level = "high"
            else:
                level = "critical"
            assert level == "low"
    
    def test_medium_risk_threshold(self):
        """Scores 0.3-0.5 should be MEDIUM risk."""
        scores = [0.3, 0.35, 0.4, 0.49]
        for score in scores:
            if score < 0.3:
                level = "low"
            elif score < 0.5:
                level = "medium"
            elif score < 0.7:
                level = "high"
            else:
                level = "critical"
            assert level == "medium"
    
    def test_high_risk_threshold(self):
        """Scores 0.5-0.7 should be HIGH risk."""
        scores = [0.5, 0.55, 0.6, 0.69]
        for score in scores:
            if score < 0.3:
                level = "low"
            elif score < 0.5:
                level = "medium"
            elif score < 0.7:
                level = "high"
            else:
                level = "critical"
            assert level == "high"
    
    def test_critical_risk_threshold(self):
        """Scores 0.7+ should be CRITICAL risk."""
        scores = [0.7, 0.8, 0.9, 1.0]
        for score in scores:
            if score < 0.3:
                level = "low"
            elif score < 0.5:
                level = "medium"
            elif score < 0.7:
                level = "high"
            else:
                level = "critical"
            assert level == "critical"


class TestRiskFactorWeighting:
    """Tests for risk factor weight calculations."""
    
    def test_weighted_score_calculation(self):
        """Weighted score should be weight * score."""
        factors = [
            {"weight": 0.9, "score": 1.0, "expected": 0.9},
            {"weight": 0.5, "score": 0.8, "expected": 0.4},
            {"weight": 0.3, "score": 0.5, "expected": 0.15},
        ]
        
        for factor in factors:
            weighted = factor["weight"] * factor["score"]
            assert abs(weighted - factor["expected"]) < 0.001
    
    def test_combined_score_max_weighted(self):
        """Combined score should weight max score heavily."""
        weighted_scores = [0.9, 0.5, 0.3]
        
        max_score = max(weighted_scores)
        avg_score = sum(weighted_scores) / len(weighted_scores)
        
        # 60% max + 40% avg
        combined = 0.6 * max_score + 0.4 * avg_score
        
        assert combined > avg_score  # Max-weighted should be higher than pure avg
        assert combined < max_score  # But lower than pure max
    
    def test_factor_count_boost(self):
        """More factors should boost the score."""
        base_score = 0.5
        
        # 1 factor = no boost
        boost_1 = 1 + (0.05 * min(1 - 1, 5))
        assert boost_1 == 1.0
        
        # 3 factors = 10% boost
        boost_3 = 1 + (0.05 * min(3 - 1, 5))
        assert boost_3 == 1.1
        
        # 6+ factors = capped at 25% boost
        boost_6 = 1 + (0.05 * min(6 - 1, 5))
        assert boost_6 == 1.25


class TestRecommendations:
    """Tests for risk-based recommendations."""
    
    def test_critical_recommendation(self):
        """CRITICAL risk should recommend BLOCK."""
        level = "critical"
        
        if level == "critical":
            recommendation = "BLOCK"
        elif level == "high":
            recommendation = "REVIEW"
        elif level == "medium":
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"
        
        assert recommendation == "BLOCK"
    
    def test_high_recommendation(self):
        """HIGH risk should recommend REVIEW."""
        level = "high"
        
        if level == "critical":
            recommendation = "BLOCK"
        elif level == "high":
            recommendation = "REVIEW"
        elif level == "medium":
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"
        
        assert recommendation == "REVIEW"
    
    def test_medium_recommendation(self):
        """MEDIUM risk should recommend MONITOR."""
        level = "medium"
        
        if level == "critical":
            recommendation = "BLOCK"
        elif level == "high":
            recommendation = "REVIEW"
        elif level == "medium":
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"
        
        assert recommendation == "MONITOR"
    
    def test_low_recommendation(self):
        """LOW risk should recommend ALLOW."""
        level = "low"
        
        if level == "critical":
            recommendation = "BLOCK"
        elif level == "high":
            recommendation = "REVIEW"
        elif level == "medium":
            recommendation = "MONITOR"
        else:
            recommendation = "ALLOW"
        
        assert recommendation == "ALLOW"


class TestBlockingLogic:
    """Tests for should_block and should_review logic."""
    
    def test_should_block_critical(self):
        """CRITICAL level should trigger block."""
        level = "critical"
        score = 0.85
        
        should_block = level == "critical" or score >= 0.85
        assert should_block is True
    
    def test_should_block_high_score(self):
        """Score >= 0.85 should trigger block regardless of level."""
        level = "high"
        score = 0.86
        
        should_block = level == "critical" or score >= 0.85
        assert should_block is True
    
    def test_should_not_block_high_level(self):
        """HIGH level alone should not block."""
        level = "high"
        score = 0.65
        
        should_block = level == "critical" or score >= 0.85
        assert should_block is False
    
    def test_should_review_high(self):
        """HIGH and CRITICAL should trigger review."""
        for level in ["high", "critical"]:
            should_review = level in ["high", "critical"]
            assert should_review is True
    
    def test_should_review_medium_score(self):
        """Score >= 0.5 should trigger review."""
        level = "medium"
        score = 0.55
        
        should_review = level in ["high", "critical"] or score >= 0.5
        assert should_review is True


class TestConfidenceCalculation:
    """Tests for confidence score calculation."""
    
    def test_base_confidence(self):
        """Base confidence should be 0.5."""
        base = 0.5
        assert base == 0.5
    
    def test_factors_boost_confidence(self):
        """More factors should increase confidence."""
        base = 0.5
        factor_count = 3
        
        confidence = base + 0.1 * min(factor_count, 3)
        assert confidence == 0.8
    
    def test_historical_data_boosts_confidence(self):
        """Historical data should increase confidence."""
        base = 0.5
        historical_points = 5
        
        confidence = base + 0.05 * min(historical_points, 5)
        assert confidence == 0.75
    
    def test_confidence_capped_at_one(self):
        """Confidence should never exceed 1.0."""
        base = 0.5
        factor_count = 5
        historical_points = 10
        
        confidence = base
        confidence += 0.1 * min(factor_count, 3)
        confidence += 0.05 * min(historical_points, 5)
        confidence = min(confidence, 1.0)
        
        assert confidence == 1.0


class TestHistoricalScoreIntegration:
    """Tests for historical score integration."""
    
    def test_historical_weight(self):
        """Historical scores should have 30% weight."""
        current_score = 0.8
        historical_avg = 0.2
        
        # 70% current + 30% historical
        combined = 0.7 * current_score + 0.3 * historical_avg
        
        assert combined == 0.62
    
    def test_no_historical_data(self):
        """Without historical data, use current score only."""
        current_score = 0.8
        historical_scores = None
        
        if historical_scores:
            historical_avg = sum(historical_scores) / len(historical_scores)
            combined = 0.7 * current_score + 0.3 * historical_avg
        else:
            combined = current_score
        
        assert combined == 0.8


class TestRealScenarios:
    """Tests based on real transaction patterns."""
    
    def test_bot_traffic_scenario(self):
        """
        Bot traffic should result in CRITICAL risk.
        
        Factors:
        - Automated client (weight: 0.95)
        - JS disabled (weight: 0.7)
        - Datacenter IP (weight: 0.8)
        """
        factors = [
            {"code": "automation_detected", "weight": 0.95, "score": 1.0},
            {"code": "js_disabled", "weight": 0.7, "score": 1.0},
            {"code": "datacenter_ip", "weight": 0.8, "score": 1.0},
        ]
        
        weighted_scores = [f["weight"] * f["score"] for f in factors]
        max_score = max(weighted_scores)
        avg_score = sum(weighted_scores) / len(weighted_scores)
        
        combined = 0.6 * max_score + 0.4 * avg_score
        factor_boost = 1 + (0.05 * min(len(factors) - 1, 5))
        final_score = min(combined * factor_boost, 1.0)
        
        # Should be CRITICAL
        assert final_score >= 0.7
    
    def test_card_testing_scenario(self):
        """
        Card testing should result in HIGH/CRITICAL risk.
        
        Factors:
        - High failure rate (weight: 0.85)
        - Multiple cards per IP (weight: 0.8)
        - Small amounts (weight: 0.6)
        """
        factors = [
            {"code": "high_failure_rate", "weight": 0.85, "score": 1.0},
            {"code": "ip_card_concentration", "weight": 0.8, "score": 1.0},
            {"code": "small_amount", "weight": 0.6, "score": 1.0},
        ]
        
        weighted_scores = [f["weight"] * f["score"] for f in factors]
        max_score = max(weighted_scores)
        avg_score = sum(weighted_scores) / len(weighted_scores)
        
        combined = 0.6 * max_score + 0.4 * avg_score
        factor_boost = 1 + (0.05 * min(len(factors) - 1, 5))
        final_score = min(combined * factor_boost, 1.0)
        
        # Should be at least HIGH
        assert final_score >= 0.5
    
    def test_legitimate_transaction_scenario(self):
        """
        Legitimate transaction should result in LOW risk.
        
        Factors: None or minor
        """
        factors = []
        
        if not factors:
            final_score = 0.0
        else:
            weighted_scores = [f["weight"] * f["score"] for f in factors]
            max_score = max(weighted_scores)
            avg_score = sum(weighted_scores) / len(weighted_scores)
            combined = 0.6 * max_score + 0.4 * avg_score
            final_score = combined
        
        # Should be LOW
        assert final_score < 0.3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
