import asyncio

import spf

from app.utils.logging import get_logger

logger = get_logger("smtp")


async def spf_pass(peer_ip: str, mail_from: str, helo: str | None) -> bool:
    # SPF 검증: SPF가 pass를 반환할 때만 수락
    # DNS 조회로 이벤트 루프가 블로킹되는 것을 방지하기 위해 executor에서 실행
    loop = asyncio.get_running_loop()
    try:
        result, _ = await loop.run_in_executor(
            None, lambda: spf.check2(i=peer_ip, s=mail_from, h=helo or "unknown")
        )
    except Exception as exc:
        logger.warning("SPF check error: %s", exc)
        return False
    return result == "pass"
