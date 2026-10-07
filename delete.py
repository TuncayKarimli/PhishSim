"""
===============================================================================
ENTERPRISE CYBER SECURITY ORCHESTRATION, AUTOMATION & THREAT INTEL ENGINE (SOAR)
===============================================================================

Модуль представляет собой полнофункциональный асинхронный движок для:
1. Сбора и парсинга событий безопасности (Syslog, Network Flow, Webhooks).
2. Корреляции событий с использованием правил стиля Sigma/YARA.
3. Проверки сущностей (IP, Hash, Domain) по базам Threat Intelligence.
4. Автоматического запуска сценариев реагирования (Playbooks).
5. Ведения состояния инцидентов и формирования аналитических отчетов.

Автор: Security Operations Architecture Team
Версия: 3.4.0-Enterprise
===============================================================================
"""

import asyncio
import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import math
import os
import re
import sys
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# =============================================================================
# 1. ГЛОБАЛЬНЫЕ КОНФИГУРАЦИИ И ЛОГИРОВАНИЕ
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("EnterpriseSOAR")


class Severity(enum.IntEnum):
    """Уровни критичности событий и инцидентов."""
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class IncidentStatus(enum.Enum):
    """Статусы жизненного цикла инцидента."""
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class EventCategory(enum.Enum):
    """Категории считываемых событий."""
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK_FLOW = "NETWORK_FLOW"
    FILE_SYSTEM = "FILE_SYSTEM"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    WEB_REQUEST = "WEB_REQUEST"


# =============================================================================
# 2. ИСКЛЮЧЕНИЯ И ИСКЛЮЧИТЕЛЬНЫЕ СИТУАЦИИ
# =============================================================================

class SOARException(Exception):
    """Базовое исключение системы SOAR."""
    pass


class RuleValidationError(SOARException):
    """Ошибка валидации синтаксиса правила обнаружения."""
    pass


class IngestionError(SOARException):
    """Ошибка при приеме или парсинге входящего события."""
    pass


class PlaybookExecutionError(SOARException):
    """Ошибка при выполнении сценария реагирования."""
    pass


# =============================================================================
# 3. МОДЕЛИ ДАННЫХ (DATA STRUCTURES & DOMAIN MODELS)
# =============================================================================

@dataclasses.dataclass
class RawEvent:
    """Сырое входящее событие от источника."""
    event_id: str
    source_ip: str
    destination_ip: str
    category: EventCategory
    payload: Dict[str, Any]
    timestamp: float = dataclasses.field(default_factory=time.time)


@dataclasses.dataclass
class ThreatIOC:
    """Индикатор компрометации (IOC)."""
    value: str
    type: str  # ip, domain, md5, sha256
    threat_actor: str
    confidence_score: float  # 0.0 -> 100.0
    description: str


@dataclasses.dataclass
class DetectionRule:
    """Правило корреляции и обнаружения аномалий."""
    rule_id: str
    name: str
    category: EventCategory
    severity: Severity
    condition_field: str
    regex_pattern: str
    threshold_count: int = 1
    time_window_seconds: int = 60
    description: str = ""


@dataclasses.dataclass
class Incident:
    """Сформированный инцидент безопасности."""
    incident_id: str
    title: str
    severity: Severity
    status: IncidentStatus
    affected_asset: str
    trigger_rule_id: str
    related_events: List[RawEvent] = dataclasses.field(default_factory=list)
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    assigned_analyst: Optional[str] = None
    mitigation_notes: List[str] = dataclasses.field(default_factory=list)


# =============================================================================
# 4. ДВИЖОК THREAT INTELLIGENCE (БАЗА ИНДИКАТОРОВ КОМПРОМЕТАЦИИ)
# =============================================================================

class ThreatIntelligenceFeed:
    """Модуль управления локальной базой знаний об угрозах (IOC)."""

    def __init__(self) -> None:
        self._iocs: Dict[str, ThreatIOC] = {}
        self._lock = asyncio.Lock()

    async def load_mock_feed(self) -> None:
        """Загрузка базовых данных об угрозах."""
        async with self._lock:
            sample_iocs = [
                ThreatIOC("192.168.1.666", "ip", "APT29", 95.0, "C2 Server"),
                ThreatIOC("malicious-domain.com", "domain", "Lazarus", 88.0, "Phishing Node"),
                ThreatIOC("e99a18c428cb38d5f260853678922e03", "md5", "LockBit", 99.0, "Ransomware Sample"),
                ThreatIOC("10.0.0.99", "ip", "Internal Scanner", 40.0, "Suspicious Recon"),
            ]
            for ioc in sample_iocs:
                self._iocs[ioc.value.lower()] = ioc
            logger.info(f"[TI Engine] Загружено {len(self._iocs)} индикаторов компрометации.")

    async def check_ioc(self, value: str) -> Optional[ThreatIOC]:
        """Проверка сущности по базе IOC."""
        async with self._lock:
            return self._iocs.get(value.lower())

    async def add_ioc(self, ioc: ThreatIOC) -> None:
        """Добавление нового индикатора в режиме реального времени."""
        async with self._lock:
            self._iocs[ioc.value.lower()] = ioc
            logger.info(f"[TI Engine] Добавлен новый IOC: {ioc.value} ({ioc.threat_actor})")


# =============================================================================
# 5. ДВИЖОК АНАЛИЗА И КОРРЕЛЯЦИИ СОБЫТИЙ (CORRELATION ENGINE)
# =============================================================================

class DetectionEngine:
    """Движок сопоставления событий с правилами безопасности."""

    def __init__(self, ti_feed: ThreatIntelligenceFeed) -> None:
        self.rules: Dict[str, DetectionRule] = {}
        self.ti_feed = ti_feed
        # Буфер событий для проверки пороговых значений (Threshold Rules)
        self._event_buffer: Dict[str, deque] = defaultdict(deque)

    def register_rule(self, rule: DetectionRule) -> None:
        """Регистрация правила обнаружения."""
        try:
            re.compile(rule.regex_pattern)
        except re.error as err:
            raise RuleValidationError(f"Ошибка в регулярном выражении правила {rule.rule_id}: {err}")
        
        self.rules[rule.rule_id] = rule
        logger.info(f"[Rule Engine] Зарегистрировано правило [{rule.rule_id}] - {rule.name}")

    async def process_event(self, event: RawEvent) -> List[Incident]:
        """Анализ входящего события на совпадение с правилами и TI."""
        generated_incidents: List[Incident] = []

        # 1. Проверка через Threat Intelligence
        src_ioc = await self.ti_feed.check_ioc(event.source_ip)
        if src_ioc and src_ioc.confidence_score > 70.0:
            incident = Incident(
                incident_id=f"INC-TI-{uuid.uuid4().hex[:8].upper()}",
                title=f"Взаимодействие с известным вредоносным IP: {event.source_ip}",
                severity=Severity.HIGH,
                status=IncidentStatus.NEW,
                affected_asset=event.destination_ip,
                trigger_rule_id="RULE-TI-MATCH",
                related_events=[event]
            )
            incident.mitigation_notes.append(f"TI Match: {src_ioc.description} (Actor: {src_ioc.threat_actor})")
            generated_incidents.append(incident)

        # 2. Проверка по набору правил корреляции
        for rule in self.rules.values():
            if rule.category != event.category:
                continue

            field_value = str(event.payload.get(rule.condition_field, ""))
            if re.search(rule.regex_pattern, field_value, re.IGNORECASE):
                # Проверка порогового значения времени и количества
                buffer_key = f"{rule.rule_id}:{event.source_ip}"
                now = time.time()
                
                buf = self._event_buffer[buffer_key]
                buf.append((now, event))

                # Очистка устаревших событий из временного окна
                while buf and (now - buf[0][0] > rule.time_window_seconds):
                    buf.popleft()

                if len(buf) >= rule.threshold_count:
                    matched_events = [e for _, e in buf]
                    buf.clear()  # Сброс буфера после срабатывания

                    inc = Incident(
                        incident_id=f"INC-DET-{uuid.uuid4().hex[:8].upper()}",
                        title=f"Срабатывание правила: {rule.name}",
                        severity=rule.severity,
                        status=IncidentStatus.NEW,
                        affected_asset=event.destination_ip,
                        trigger_rule_id=rule.rule_id,
                        related_events=matched_events
                    )
                    generated_incidents.append(inc)

        return generated_incidents


# =============================================================================
# 6. СИСТЕМА АВТОМАТИЧЕСКОГО РЕАГИРОВАНИЯ (SOAR PLAYBOOKS)
# =============================================================================

class AbstractPlaybook(ABC):
    """Абстрактный класс для сценариев реагирования."""

    @abstractmethod
    async def execute(self, incident: Incident) -> bool:
        """Запуск логики реагирования."""
        pass


class BlockIPPlaybook(AbstractPlaybook):
    """Сценарий автоматической блокировки IP-адреса на фаерволе."""

    async def execute(self, incident: Incident) -> bool:
        if not incident.related_events:
            return False

        target_ip = incident.related_events[0].source_ip
        logger.warning(f"[PLAYBOOK] >>> Исполнение блокировки IP {target_ip} на Edge Firewall...")
        
        # Симуляция сетевого запроса к сетевому оборудованию / API фаервола
        await asyncio.sleep(0.1)
        
        incident.mitigation_notes.append(f"[Auto-Mitigation] IP {target_ip} заблокирован на 24 часа.")
        incident.status = IncidentStatus.CONTAINED
        logger.info(f"[PLAYBOOK] <<< IP {target_ip} успешно заблокирован. Инцидент {incident.incident_id} изолирован.")
        return True


class IsolateHostPlaybook(AbstractPlaybook):
    """Сценарий изоляции компрометированного хоста от сети."""

    async def execute(self, incident: Incident) -> bool:
        target_asset = incident.affected_asset
        logger.warning(f"[PLAYBOOK] >>> Сетевая изоляция хоста {target_asset} через EDR агент...")
        
        await asyncio.sleep(0.2)
        
        incident.mitigation_notes.append(f"[Auto-Mitigation] Хост {target_asset} изолирован от локальной сети.")
        incident.status = IncidentStatus.CONTAINED
        logger.info(f"[PLAYBOOK] <<< Хост {target_asset} изолирован.")
        return True


class PlaybookOrchestrator:
    """Оркестратор распределения и запуска сценариев реагирования."""

    def __init__(self) -> None:
        self._playbooks: Dict[Severity, List[AbstractPlaybook]] = defaultdict(list)

    def register_playbook(self, severity: Severity, playbook: AbstractPlaybook) -> None:
        """Привязка сценария реагирования к уровню критичности."""
        self._playbooks[severity].append(playbook)

    async def handle_incident(self, incident: Incident) -> None:
        """Запуск применимых сценариев для инцидента."""
        playbooks = self._playbooks.get(incident.severity, [])
        if not playbooks:
            logger.info(f"[SOAR Orchestrator] Для уровня {incident.severity.name} нет авто-сценариев.")
            return

        for pb in playbooks:
            try:
                success = await pb.execute(incident)
                if success:
                    logger.info(f"[SOAR Orchestrator] Сценарий {pb.__class__.__name__} выполнен успешно.")
            except Exception as ex:
                logger.error(f"[SOAR Orchestrator] Ошибка выполнения {pb.__class__.__name__}: {ex}")
                raise PlaybookExecutionError(f"Сбой плейбука: {ex}")


# =============================================================
# 7. ХРАНИЛИЩЕ СОСТОЯНИЯ И ИНЦИДЕНТОВ (PERSISTENCE LAYER)
# =============================================================

class IncidentRepository:
    """In-memory репозиторий для хранения и поиска инцидентов."""

    def __init__(self) -> None:
        self._incidents: Dict[str, Incident] = {}
        self._lock = asyncio.Lock()

    async def save(self, incident: Incident) -> None:
        async with self._lock:
            self._incidents[incident.incident_id] = incident

    async def get_by_id(self, incident_id: str) -> Optional[Incident]:
        async with self._lock:
            return self._incidents.get(incident_id)

    async def get_all(self) -> List[Incident]:
        async with self._lock:
            return list(self._incidents.values())

    async def export_json(self) -> str:
        """Экспорт всех инцидентов в формат JSON."""
        async with self._lock:
            export_data = []
            for inc in self._incidents.values():
                export_data.append({
                    "incident_id": inc.incident_id,
                    "title": inc.title,
                    "severity": inc.severity.name,
                    "status": inc.status.value,
                    "affected_asset": inc.affected_asset,
                    "notes": inc.mitigation_notes,
                    "created_at": inc.created_at
                })
            return json.dumps(export_data, indent=2, ensure_ascii=False)


# =============================================================
# 8. ГЕНЕРАТОР ПОТОКА СОБЫТИЙ (EVENT INGESTION PIPELINE)
# =============================================================

class EventStreamSimulator:
    """Симулятор потока сырых событий от сетевых устройств и агентов."""

    def __init__(self, output_queue: asyncio.Queue) -> None:
        self.output_queue = output_queue
        self._running = False

    async def start(self) -> None:
        self._running = True
        logger.info("[Ingestion Pipeline] Запуск приемника входящих событий...")

        # Набор тестовых сценариев событий
        sample_scenarios = [
            # 1. Попытки подобрать пароль (Brute Force)
            lambda: RawEvent(
                event_id=str(uuid.uuid4()),
                source_ip="192.168.1.105",
                destination_ip="10.0.0.1",
                category=EventCategory.AUTHENTICATION,
                payload={"username": "admin", "status": "FAILED_LOGIN", "port": 22}
            ),
            # 2. Обычный веб-запрос
            lambda: RawEvent(
                event_id=str(uuid.uuid4()),
                source_ip="10.0.0.50",
                destination_ip="10.0.0.10",
                category=EventCategory.WEB_REQUEST,
                payload={"uri": "/index.html", "status_code": 200, "user_agent": "Mozilla/5.0"}
            ),
            # 3. Веб-атака (SQL Injection)
            lambda: RawEvent(
                event_id=str(uuid.uuid4()),
                source_ip="172.16.0.44",
                destination_ip="10.0.0.10",
                category=EventCategory.WEB_REQUEST,
                payload={"uri": "/login.php?id=1' UNION SELECT NULL, username, password FROM users--", "status_code": 500}
            ),
            # 4. Событие от известного злоумышленника (TI Match)
            lambda: RawEvent(
                event_id=str(uuid.uuid4()),
                source_ip="192.168.1.666",
                destination_ip="10.0.0.5",
                category=EventCategory.NETWORK_FLOW,
                payload={"bytes_sent": 50400, "protocol": "TCP", "port": 443}
            ),
        ]

        idx = 0
        while self._running:
            await asyncio.sleep(0.05)  # Высокая скорость генерации
            event_factory = sample_scenarios[idx % len(sample_scenarios)]
            event = event_factory()
            await self.output_queue.put(event)
            idx += 1

    def stop(self) -> None:
        self._running = False


# =============================================================
# 9. ЯДРО ОРКЕСТРАЦИИ СИСТЕМЫ (MAIN SYSTEM DAEMON)
# =============================================================

class SecurityOperationsDaemon:
    """Главный оркестратор системы SOAR."""

    def __init__(self) -> None:
        self.event_queue: asyncio.Queue[RawEvent] = asyncio.Queue()
        self.ti_feed = ThreatIntelligenceFeed()
        self.detection_engine = DetectionEngine(self.ti_feed)
        self.playbook_orchestrator = PlaybookOrchestrator()
        self.repository = IncidentRepository()
        self.simulator = EventStreamSimulator(self.event_queue)
        self._stop_event = asyncio.Event()

    async def initialize(self) -> None:
        """Инициализация модулей, загрузка правил и плейбуков."""
        logger.info("[System] Инициализация SOAR платформы...")
        await self.ti_feed.load_mock_feed()

        # Регистрация правил корреляции
        self.detection_engine.register_rule(
            DetectionRule(
                rule_id="RULE-001",
                name="Brute Force Authentication Attempt",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                condition_field="status",
                regex_pattern="FAILED_LOGIN",
                threshold_count=3,
                time_window_seconds=10,
                description="Обнаружена серия неудачных попыток аутентификации."
            )
        )

        self.detection_engine.register_rule(
            DetectionRule(
                rule_id="RULE-002",
                name="SQL Injection Attack Detected",
                category=EventCategory.WEB_REQUEST,
                severity=Severity.CRITICAL,
                condition_field="uri",
                regex_pattern="(UNION|SELECT|INSERT|DELETE|--|')",
                threshold_count=1,
                time_window_seconds=5,
                description="В сигнатуре URI обнаружены конструкции SQL-инъекции."
            )
        )

        # Регистрация плейбуков реагирования
        self.playbook_orchestrator.register_playbook(Severity.HIGH, BlockIPPlaybook())
        self.playbook_orchestrator.register_playbook(Severity.CRITICAL, BlockIPPlaybook())
        self.playbook_orchestrator.register_playbook(Severity.CRITICAL, IsolateHostPlaybook())

        logger.info("[System] Инициализация завершена успешно.")

    async def _processing_loop(self) -> None:
        """Главный асинхронный цикл обработки событий."""
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Анализ события
            incidents = await self.detection_engine.process_event(event)

            # Обработка созданных инцидентов
            for inc in incidents:
                logger.warning(f"[DETECTION] >>> Создан инцидент [{inc.incident_id}] ({inc.severity.name}): {inc.title}")
                await self.repository.save(inc)
                
                # Запуск автоматического реагирования
                await self.playbook_orchestrator.handle_incident(inc)
                
                # Обновление состояния инцидента
                await self.repository.save(inc)

            self.event_queue.task_done()

    async def run(self, runtime_seconds: int = 3) -> None:
        """Запуск сервиса на определенное время."""
        await self.initialize()

        # Запуск фоновых задач
        processing_task = asyncio.create_task(self._processing_loop())
        simulator_task = asyncio.create_task(self.simulator.start())

        logger.info(f"[System] Движок запущен. Время симуляции: {runtime_seconds} сек.")
        await asyncio.sleep(runtime_seconds)

        # Остановка системы
        logger.info("[System] Остановка работы и завершение процессов...")
        self.simulator.stop()
        self._stop_event.set()

        await asyncio.gather(processing_task, simulator_task, return_exceptions=True)

        # Вывод итогового отчета
        await self._print_final_report()

    async def _print_final_report(self) -> None:
        """Печать детального отчета по найденным инцидентам."""
        incidents = await self.repository.get_all()
        print("\n" + "=" * 80)
        print(f"ИТОГОВЫЙ ОТЧЕТ ИНЦИДЕНТОВ БЕЗОПАСНОСТИ (ВСЕГО: {len(incidents)})")
        print("=" * 80)

        for inc in incidents:
            print(f"ИД Инцидента   : {inc.incident_id}")
            print(f"Название       : {inc.title}")
            print(f"Критичность    : {inc.severity.name}")
            print(f"Статус         : {inc.status.value}")
            print(f"Целевой ресурс : {inc.affected_asset}")
            print(f"Действия SOAR  : {', '.join(inc.mitigation_notes)}")
            print("-" * 80)


# =============================================================
# 10. ТОЧКА ВХОДА (ENTRY POINT)
# =============================================================

if __name__ == "__main__":
    daemon = SecurityOperationsDaemon()
    try:
        asyncio.run(daemon.run(runtime_seconds=3))
    except KeyboardInterrupt:
        logger.info("Программа остановлена пользователем.")
