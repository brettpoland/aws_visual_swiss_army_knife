import pytest

from main import get_region_from_arn


def test_region_extraction():
    arn = "arn:aws:lambda:us-west-2:123456789012:function:my-func"
    assert get_region_from_arn(arn) == "us-west-2"


def test_s3_arn_without_region():
    arn = "arn:aws:s3:::my_corporate_bucket"
    assert get_region_from_arn(arn) is None


def test_invalid_arn_raises():
    with pytest.raises(ValueError):
        get_region_from_arn("not-an-arn")
