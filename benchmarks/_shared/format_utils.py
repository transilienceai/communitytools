"""Small text-formatting helpers used across runners."""


def format_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def progress_bar(value: int, total: int, width: int = 20) -> str:
    if total == 0:
        return ""
    filled = int(width * value / total)
    return f"[{'#' * filled}{'.' * (width - filled)}] {value / total * 100:.0f}%"
