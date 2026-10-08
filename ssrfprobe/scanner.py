"""Asynchronous SSRF scanning and payload injection engine."""

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ssrfprobe.payloads import SUSPICIOUS_PARAMS, TARGET_HEADERS, generate_bypass_payloads

# Common signature markers leaked by cloud metadata or internal panels
SENSITIVE_SIGNATURES = [
    "ami-id",
    "instance-id",
    "computeMetadata",
    "security-credentials",
    "kube-env",
    "internal server error",
]


class SSRFScanner:
    """Core scanner class for executing asynchronous SSRF checks."""

    def __init__(
        self,
        concurrency: int = 15,
        timeout: float = 7.0,
        verify_ssl: bool = False,
        headers: Optional[Dict[str, str]] = None,
        collab: str = "",
    ):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = httpx.Timeout(timeout, connect=5.0)
        self.verify_ssl = verify_ssl
        self.base_headers = headers or {"User-Agent": "SSRFProbe/1.0"}
        self.payloads = generate_bypass_payloads(collaborator_url=collab)

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        marker: str,
    ) -> Optional[Dict[str, Any]]:
        """Sends an isolated HTTP request and evaluates the response for SSRF indicators."""
        async with self.semaphore:
            try:
                response = await client.get(
                    url,
                    headers=headers,
                    follow_redirects=False,
                )

                content_sample = response.text[:4000].lower()
                signature_hit = any(sig.lower() in content_sample for sig in SENSITIVE_SIGNATURES)

                # Heuristic flag: Status codes indicating internal responses or signature match
                is_interesting = (
                    response.status_code in (200, 301, 302, 307)
                    or signature_hit
                )

                return {
                    "url": url,
                    "marker": marker,
                    "status": response.status_code,
                    "length": len(response.content),
                    "interesting": is_interesting,
                    "signature_hit": signature_hit,
                }
            except (httpx.RequestError, httpx.TimeoutException):
                return None

    def _inject_params(self, base_url: str, payload: str) -> List[str]:
        """Injects payloads into existing query parameters or default suspicious parameters."""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        injected_urls: List[str] = []

        if params:
            for param_key in params:
                temp_params = params.copy()
                temp_params[param_key] = [payload]
                new_query = urlencode(temp_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                injected_urls.append(new_url)
        else:
            # If no parameters exist, inject the top common parameters
            for sp in SUSPICIOUS_PARAMS[:5]:
                new_query = urlencode({sp: payload})
                new_url = urlunparse(parsed._replace(query=new_query))
                injected_urls.append(new_url)

        return injected_urls

    async def scan_target(self, client: httpx.AsyncClient, target_url: str) -> List[Dict[str, Any]]:
        """Executes all parameter and header injection tasks against a given target."""
        results: List[Dict[str, Any]] = []
        tasks = []

        # 1. Parameter fuzzing
        for payload in self.payloads:
            injected_urls = self._inject_params(target_url, payload)
            for i_url in injected_urls:
                tasks.append(
                    self._send_request(
                        client,
                        i_url,
                        self.base_headers,
                        f"Param Injection: {payload}",
                    )
                )

        # 2. Header fuzzing
        for payload in self.payloads:
            for header_name in TARGET_HEADERS:
                custom_headers = self.base_headers.copy()
                custom_headers[header_name] = payload
                tasks.append(
                    self._send_request(
                        client,
                        target_url,
                        custom_headers,
                        f"Header [{header_name}]: {payload}",
                    )
                )

        completed = await asyncio.gather(*tasks, return_exceptions=True)
        for res in completed:
            if isinstance(res, dict) and res is not None:
                results.append(res)

        return results
