"""AWS Visual Swiss Army Knife utilities."""

from __future__ import annotations


def get_region_from_arn(arn: str) -> str | None:
    """Extract the region component from an AWS ARN.

    Parameters
    ----------
    arn:
        Full Amazon Resource Name.

    Returns
    -------
    str | None
        Region string if present. Returns ``None`` if the ARN does not
        include a region component.

    Raises
    ------
    ValueError
        If the ARN does not have the expected structure.
    """
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        raise ValueError(f"Malformed ARN: {arn}")

    region = parts[3]
    return region or None


if __name__ == "__main__":
    import sys

    if not sys.argv[1:]:
        raise SystemExit("usage: python main.py <arn>")

    print(get_region_from_arn(sys.argv[1]))
