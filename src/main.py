#!/usr/bin/env python3
"""
Zhen Professional Shodan & Censys Search Toolkit
Advanced search query generation and automation tool for security professionals
Author: Oscar Valois
Version: 1.0.0
"""

import sys
import json
import logging
import datetime
import asyncio
import aiohttp
import pandas as pd
import sqlite3
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
from dataclasses import dataclass
import yaml
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import csv
import os
from functools import partial
import hashlib
import re
import ipaddress
from PyQt6.QtWidgets import QInputDialog
from PyQt6.QtCore import Qt
# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit, QTabWidget,
    QGroupBox, QRadioButton, QListWidget, QTableWidget, QGridLayout,
    QMessageBox, QFileDialog, QCheckBox, QSpinBox, QTableWidgetItem,
    QProgressBar, QSplitter, QFrame, QScrollArea, QStatusBar, QMenu,
    QListWidgetItem, QTreeWidget, QTreeWidgetItem,  # Agregamos estas importaciones
    QStyle  # También necesario para los íconos de estado
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QSettings, QTimer, QSize, QRect,
    QPoint, QUrl, QMutex, 
    QRegularExpression,  # Para expresiones regulares
    QRegularExpressionMatch  # Para coincidencias de regex
)
from PyQt6.QtGui import (
    QFont, QIcon, QPalette, QColor, QPixmap, QAction, QKeySequence,
    QTextCursor, QTextCharFormat, QSyntaxHighlighter, QTextFormat,
    QTextDocument  # Para búsqueda y manipulación de documento
)
# Third-party imports
import shodan
import censys.search
import requests
import rich
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import plotly.express as px
import plotly.graph_objects as go
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Constants and Configuration
CONFIG_FILE = 'config/config.yaml'
DB_FILE = 'data/searchkit.db'
LOG_FILE = 'logs/searchkit.log'
TEMPLATE_DIR = 'data/templates'
EXPORT_DIR = 'exports'
VERSION = '1.0.0'

# Initialize Rich console
console = Console()

@dataclass
class SearchResult:
    """Data class for search results"""
    timestamp: datetime.datetime
    platform: str
    query: str
    results: List[Dict]
    metadata: Dict
    execution_time: float

class SearchError(Exception):
    """Custom exception for search-related errors"""
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration-related errors"""
    pass

class APIError(Exception):
    """Custom exception for API-related errors"""
    pass

class DatabaseManager:
    """Manages all database operations"""
    
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.mutex = QMutex()
        self.init_database()

    def init_database(self):
        """Initialize database with required tables"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                -- Queries table
                CREATE TABLE IF NOT EXISTS queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    query TEXT NOT NULL,
                    tags TEXT,
                    category TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    success_rate FLOAT DEFAULT 0.0,
                    favorite BOOLEAN DEFAULT 0,
                    execution_count INTEGER DEFAULT 0,
                    average_execution_time FLOAT DEFAULT 0.0
                );

                -- Results table
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_id INTEGER,
                    platform TEXT NOT NULL,
                    results_json TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    execution_time FLOAT,
                    result_count INTEGER,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    metadata_json TEXT,
                    FOREIGN KEY (query_id) REFERENCES queries (id)
                );

                -- Templates table
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT,
                    platform TEXT NOT NULL,
                    query_template TEXT NOT NULL,
                    parameters TEXT,
                    description TEXT,
                    usage_count INTEGER DEFAULT 0,
                    last_used TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    author TEXT,
                    version TEXT
                );

                -- Saved searches table
                CREATE TABLE IF NOT EXISTS saved_searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    query_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    schedule TEXT,
                    last_run TIMESTAMP,
                    next_run TIMESTAMP,
                    enabled BOOLEAN DEFAULT 1,
                    notification_email TEXT,
                    FOREIGN KEY (query_id) REFERENCES queries (id)
                );

                -- Create indexes
                CREATE INDEX IF NOT EXISTS idx_queries_platform ON queries(platform);
                CREATE INDEX IF NOT EXISTS idx_results_query_id ON results(query_id);
                CREATE INDEX IF NOT EXISTS idx_templates_category ON templates(category);
            ''')

    def add_query(self, name: str, platform: str, query: str, **kwargs) -> int:
        """Add a new query to the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO queries (name, platform, query, tags, category, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, platform, query, 
                 kwargs.get('tags'), 
                 kwargs.get('category'),
                 kwargs.get('description')))
            return cursor.lastrowid
    def get_templates_by_category(self, category: str) -> List[Dict]:
        """
        Obtiene todos los templates de una categoría específica con funcionalidad extendida
        
        Args:
            category (str): Nombre de la categoría a buscar
            
        Returns:
            List[Dict]: Lista de templates con toda su información
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Consulta principal para obtener templates
                cursor.execute("""
                    SELECT 
                        t.*,
                        (SELECT COUNT(*) FROM template_usage WHERE template_id = t.id) as usage_count,
                        (SELECT MAX(timestamp) FROM template_usage WHERE template_id = t.id) as last_used,
                        (SELECT GROUP_CONCAT(tag) FROM template_tags WHERE template_id = t.id) as tags,
                        (SELECT COUNT(*) FROM template_validations WHERE template_id = t.id AND is_valid = 1) as valid_uses,
                        (SELECT COUNT(*) FROM template_validations WHERE template_id = t.id AND is_valid = 0) as invalid_uses
                    FROM templates t
                    WHERE t.category = ?
                    ORDER BY t.name
                """, (category,))
                
                templates = []
                for row in cursor.fetchall():
                    template_data = dict(row)
                    
                    # Procesar parámetros JSON
                    try:
                        template_data['parameters'] = json.loads(template_data['parameters'])
                    except (json.JSONDecodeError, TypeError):
                        template_data['parameters'] = {}
                    
                    # Procesar tags
                    template_data['tags'] = (
                        template_data['tags'].split(',') 
                        if template_data['tags'] 
                        else []
                    )
                    
                    # Calcular estadísticas adicionales
                    template_data['success_rate'] = self.calculate_template_success_rate(
                        template_data['valid_uses'],
                        template_data['invalid_uses']
                    )
                    
                    # Obtener ejemplos de uso
                    template_data['examples'] = self.get_template_examples(
                        template_data['id']
                    )
                    
                    # Obtener historial de modificaciones
                    template_data['modification_history'] = self.get_template_modifications(
                        template_data['id']
                    )
                    
                    # Verificar compatibilidad de plataforma
                    template_data['platform_compatibility'] = self.check_platform_compatibility(
                        template_data['query_template'],
                        template_data['platform']
                    )
                    
                    templates.append(template_data)
                
                return templates
                
        except Exception as e:
            logging.error(f"Error getting templates by category: {e}")
            raise DatabaseError(f"Failed to retrieve templates: {str(e)}")
    def calculate_template_success_rate(self, valid_uses: int, invalid_uses: int) -> float:
        """
        Calcula la tasa de éxito de un template
        
        Args:
            valid_uses (int): Número de usos válidos
            invalid_uses (int): Número de usos inválidos
            
        Returns:
            float: Porcentaje de éxito
        """
        total_uses = valid_uses + invalid_uses
        if total_uses == 0:
            return 0.0
        return (valid_uses / total_uses) * 100

    def get_template_examples(self, template_id: int) -> List[Dict]:
        """
        Obtiene ejemplos de uso del template
        
        Args:
            template_id (int): ID del template
            
        Returns:
            List[Dict]: Lista de ejemplos de uso
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        tu.*,
                        q.query as generated_query,
                        q.platform,
                        r.result_count,
                        r.execution_time
                    FROM template_usage tu
                    LEFT JOIN queries q ON tu.query_id = q.id
                    LEFT JOIN results r ON q.id = r.query_id
                    WHERE tu.template_id = ?
                    ORDER BY tu.timestamp DESC
                    LIMIT 5
                """, (template_id,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logging.error(f"Error getting template examples: {e}")
            return []

    def get_template_modifications(self, template_id: int) -> List[Dict]:
        """
        Obtiene el historial de modificaciones del template
        
        Args:
            template_id (int): ID del template
            
        Returns:
            List[Dict]: Lista de modificaciones
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT *
                    FROM template_modifications
                    WHERE template_id = ?
                    ORDER BY timestamp DESC
                """, (template_id,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logging.error(f"Error getting template modifications: {e}")
            return []

    def check_platform_compatibility(self, query_template: str, platform: str) -> Dict:
        """
        Verifica la compatibilidad del template con la plataforma
        
        Args:
            query_template (str): Template de consulta
            platform (str): Plataforma objetivo
            
        Returns:
            Dict: Información de compatibilidad
        """
        try:
            compatibility = {
                'is_compatible': True,
                'warnings': [],
                'suggestions': []
            }
            
            # Verificar sintaxis específica de la plataforma
            if platform.lower() == 'shodan':
                self.check_shodan_compatibility(query_template, compatibility)
            elif platform.lower() == 'censys':
                self.check_censys_compatibility(query_template, compatibility)
                
            return compatibility
            
        except Exception as e:
            logging.error(f"Error checking platform compatibility: {e}")
            return {'is_compatible': False, 'warnings': [str(e)], 'suggestions': []}

    def check_shodan_compatibility(self, query_template: str, compatibility: Dict):
        """
        Verifica la compatibilidad con Shodan
        
        Args:
            query_template (str): Template de consulta
            compatibility (Dict): Diccionario de compatibilidad a actualizar
        """
        # Verificar operadores Shodan requeridos
        required_operators = ['port:', 'country:', 'org:', 'hostname:']
        for operator in required_operators:
            if operator not in query_template:
                compatibility['warnings'].append(
                    f"Template might be missing common Shodan operator: {operator}"
                )
        
        # Verificar sintaxis de filtros
        if ':' not in query_template:
            compatibility['is_compatible'] = False
            compatibility['warnings'].append(
                "Shodan queries require at least one filter (operator:value)"
            )
        
        # Verificar rangos IP
        ip_ranges = re.findall(r'net:\s*([^\s]+)', query_template)
        for ip_range in ip_ranges:
            try:
                ipaddress.ip_network(ip_range.strip('[]'))
            except ValueError:
                compatibility['warnings'].append(f"Invalid IP range format: {ip_range}")

    def check_censys_compatibility(self, query_template: str, compatibility: Dict):
        """
        Verifica la compatibilidad con Censys
        
        Args:
            query_template (str): Template de consulta
            compatibility (Dict): Diccionario de compatibilidad a actualizar
        """
        # Verificar sintaxis de Censys
        if '.' not in query_template or ':' not in query_template:
            compatibility['is_compatible'] = False
            compatibility['warnings'].append(
                "Censys queries should use field notation (service.field:value)"
            )
        
        # Verificar campos comunes
        common_fields = ['services.port', 'location.country', 'autonomous_system.name']
        for field in common_fields:
            if field not in query_template:
                compatibility['suggestions'].append(
                    f"Consider using common Censys field: {field}"
                )
        
        # Verificar operadores de comparación
        if not any(op in query_template for op in ['>=', '<=', '=', ':']):
            compatibility['warnings'].append(
                "Query might be missing comparison operators"
            )

class DatabaseError(Exception):
    """Excepción personalizada para errores de base de datos"""
    pass

    def add_result(self, query_id: int, result: SearchResult):
        """Add a search result to the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO results (
                    query_id, platform, results_json, execution_time,
                    result_count, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                query_id,
                result.platform,
                json.dumps(result.results),
                result.execution_time,
                len(result.results),
                json.dumps(result.metadata)
            ))

    def get_recent_queries(self, limit: int = 10) -> List[Dict]:
        """Get recently used queries"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM queries
                ORDER BY last_used DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_favorite_queries(self) -> List[Dict]:
        """Get favorite queries"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM queries WHERE favorite = 1')
            return [dict(row) for row in cursor.fetchall()]

    def update_query_stats(self, query_id: int, execution_time: float, success: bool):
        """Update query statistics after execution"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE queries
                SET last_used = CURRENT_TIMESTAMP,
                    execution_count = execution_count + 1,
                    average_execution_time = ((average_execution_time * execution_count) + ?) / (execution_count + 1),
                    success_rate = ((success_rate * execution_count) + ?) / (execution_count + 1)
                WHERE id = ?
            ''', (execution_time, 1 if success else 0, query_id))

class APIManager:
    def __init__(self, api_keys: Dict[str, str]):
        self.shodan_api = shodan.Shodan(api_keys.get('shodan'))
        
        # Inicializar Censys solo si tenemos las credenciales
        if api_keys.get('censys_id') and api_keys.get('censys_secret'):
            self.censys_api = censys.search.CensysHosts(
                api_id=api_keys.get('censys_id'),
                api_secret=api_keys.get('censys_secret')
            )
        else:
            self.censys_api = None
            
        # Crear el event loop
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.session = None
        
        self.rate_limits = {
            'shodan': {'calls': 0, 'last_reset': time.time()},
            'censys': {'calls': 0, 'last_reset': time.time()}
        }

    async def init_session(self):
        """Initialize aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    async def search_shodan(self, query: str) -> SearchResult:
        """
        Ejecuta una búsqueda en Shodan
        
        Args:
            query (str): Query de búsqueda
            
        Returns:
            SearchResult: Resultados de la búsqueda estructurados
            
        Raises:
            APIError: Si hay un error con la API
            RateLimitError: Si se exceden los límites de tasa
        """
        try:
            # Verificar límites de tasa
            current_time = time.time()
            if current_time - self.rate_limits['shodan']['last_reset'] >= 1:
                self.rate_limits['shodan']['calls'] = 0
                self.rate_limits['shodan']['last_reset'] = current_time
                
            if self.rate_limits['shodan']['calls'] >= 1:
                raise RateLimitError("Shodan rate limit exceeded. Please wait.")
                
            self.rate_limits['shodan']['calls'] += 1
            
            start_time = time.time()
            
            # Ejecutar búsqueda
            results = []
            try:
                # Usar el cliente shodan para búsqueda
                search_results = self.shodan_api.search(query, limit=100)
                
                for result in search_results['matches']:
                    processed_result = {
                        'ip': result.get('ip_str'),
                        'port': result.get('port'),
                        'hostnames': result.get('hostnames', []),
                        'org': result.get('org'),
                        'country_name': result.get('location', {}).get('country_name'),
                        'timestamp': result.get('timestamp'),
                        'product': result.get('product', ''),
                        'version': result.get('version', ''),
                        'vulns': result.get('vulns', []),
                        'ssl': result.get('ssl', {}),
                        'protocols': result.get('protocols', []),
                        'services': result.get('services', []),
                        'data': result.get('data', '')
                    }
                    results.append(processed_result)
                    
            except shodan.APIError as e:
                raise APIError(f"Shodan API error: {str(e)}")
                
            execution_time = time.time() - start_time
            
            # Preparar metadata
            metadata = {
                'total_results': len(results),
                'query': query,
                'execution_time': execution_time,
                'rate_limit_remaining': self.shodan_api.info()['query_credits'],
                'scan_credits_remaining': self.shodan_api.info()['scan_credits']
            }
            
            return SearchResult(
                timestamp=datetime.datetime.now(),
                platform='shodan',
                query=query,
                results=results,
                metadata=metadata,
                execution_time=execution_time
            )
            
        except Exception as e:
            logging.error(f"Error in Shodan search: {e}")
            raise
    async def search_censys(self, query: str) -> SearchResult:
        """
        Ejecuta una búsqueda en Censys
        
        Args:
            query (str): Query de búsqueda
            
        Returns:
            SearchResult: Resultados de la búsqueda estructurados
            
        Raises:
            APIError: Si hay un error con la API
            RateLimitError: Si se exceden los límites de tasa
        """
        try:
            # Verificar límites de tasa
            current_time = time.time()
            if current_time - self.rate_limits['censys']['last_reset'] >= 1:
                self.rate_limits['censys']['calls'] = 0
                self.rate_limits['censys']['last_reset'] = current_time
                
            if self.rate_limits['censys']['calls'] >= 1:
                raise RateLimitError("Censys rate limit exceeded. Please wait.")
                
            self.rate_limits['censys']['calls'] += 1
            
            start_time = time.time()
            
            # Ejecutar búsqueda
            results = []
            try:
                # Usar el cliente censys para búsqueda
                search_results = self.censys_api.search(query, per_page=100)
                
                for result in search_results:
                    processed_result = {
                        'ip': result.get('ip'),
                        'services': result.get('services', []),
                        'location': {
                            'country': result.get('location', {}).get('country'),
                            'city': result.get('location', {}).get('city'),
                            'coordinates': result.get('location', {}).get('coordinates')
                        },
                        'autonomous_system': {
                            'name': result.get('autonomous_system', {}).get('name'),
                            'organization': result.get('autonomous_system', {}).get('organization')
                        },
                        'last_updated': result.get('last_updated_at'),
                        'ports': result.get('ports', []),
                        'protocols': result.get('protocols', []),
                        'operating_system': result.get('operating_system', {}),
                        'certificates': [
                            {
                                'fingerprint': cert.get('fingerprint'),
                                'issuer': cert.get('issuer'),
                                'subject': cert.get('subject'),
                                'validity': cert.get('validity')
                            }
                            for cert in result.get('certificates', [])
                        ]
                    }
                    results.append(processed_result)
                    
            except censys.base.CensysException as e:
                raise APIError(f"Censys API error: {str(e)}")
                
            execution_time = time.time() - start_time
            
            # Preparar metadata
            metadata = {
                'total_results': len(results),
                'query': query,
                'execution_time': execution_time
            }
            
            return SearchResult(
                timestamp=datetime.datetime.now(),
                platform='censys',
                query=query,
                results=results,
                metadata=metadata,
                execution_time=execution_time
            )
            
        except Exception as e:
            logging.error(f"Error in Censys search: {e}")
            raise
class RateLimitError(Exception):
    """Excepción personalizada para errores de límite de tasa"""
    pass    
class SearchWorker(QThread):
    """Worker thread for executing searches"""
    
    finished = pyqtSignal(SearchResult)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, api_manager: APIManager, platform: str, query: str):
        super().__init__()
        self.api_manager = api_manager
        self.platform = platform
        self.query = query

    async def execute_search(self):
        """Execute the search based on platform"""
        if self.platform == 'shodan':
            return await self.api_manager.search_shodan(self.query)
        elif self.platform == 'censys':
            return await self.api_manager.search_censys(self.query)
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")

    def run(self):
        """Run the search operation"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.execute_search())
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()

class QueryBuilder:
    """Advanced query builder with templates and validation"""
    
    def __init__(self):
        self.load_templates()
        self.load_operators()

    def load_templates(self):
        """Load query templates from YAML files"""
        self.templates = {}
        template_path = Path(TEMPLATE_DIR)
        template_path.mkdir(parents=True, exist_ok=True)
        
        for template_file in template_path.glob('*.yaml'):
            try:
                with open(template_file) as f:
                    category_templates = yaml.safe_load(f)
                    self.templates.update(category_templates)
            except Exception as e:
                logging.error(f"Error loading template {template_file}: {e}")

    def load_operators(self):
        """Load search operators from configuration"""
        try:
            with open('config/operators.yaml') as f:
                self.operators = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading operators: {e}")
            self.operators = {}

    def validate_query(self, platform: str, query: str) -> tuple[bool, str]:
        """Validate a search query"""
        if not query.strip():
            return False, "Query cannot be empty"
        
        if platform == 'shodan':
            # Validate Shodan-specific syntax
            if ':' not in query:
                return False, "Shodan query must contain at least one filter (operator:value)"
            
            # Check for valid IP ranges
            ip_ranges = re.findall(r'net:\s*([^\s]+)', query)
            for ip_range in ip_ranges:
                try:
                    ipaddress.ip_network(ip_range)
                except ValueError:
                    return False, f"Invalid IP range: {ip_range}"
                    
        elif platform == 'censys':
            # Validate Censys-specific syntax
            if '.' not in query or ':' not in query:
                return False, "Censys query must use proper field notation (service.field: value)"
        
        return True, "Valid query"

    def build_query(self, platform: str, params: Dict) -> str:
        """Build a search query from parameters"""
        if platform not in self.operators:
            raise ValueError(f"Unsupported platform: {platform}")
        
        query_parts = []
        operators = self.operators[platform]
        
        for param, value in params.items():
            if param in operators:
                if isinstance(value, list):
                    subparts = [operators[param].format(v) for v in value]
                    query_parts.append(f"({' OR '.join(subparts)})")
                else:
                    query_parts.append(operators[param].format(value))
        
        query = ' AND '.join(query_parts)
        is_valid, message = self.validate_query(platform, query)
        if not is_valid:
            raise ValueError(message)
        
        return query

    def get_template(self, name: str) -> Dict:
        """Get a query template by name"""
        if name not in self.templates:
            raise ValueError(f"Template not found: {name}")
        return self.templates[name]

class ResultsAnalyzer:
    """Analyzes and processes search results"""
    
    def __init__(self):
        self.df = None

    def load_results(self, results: SearchResult):
        """Load results into a pandas DataFrame for analysis"""
        self.df = pd.DataFrame(results.results)
        self.platform = results.platform
        self.query = results.query
        self.timestamp = results.timestamp

    def generate_statistics(self) -> Dict:
        """Generate statistical analysis of results"""
        if self.df is None:
            return {}

        stats = {
            'total_results': len(self.df),
            'timestamp': self.timestamp,
            'platform': self.platform,
            'query': self.query
        }

        # Platform-specific statistics
        if self.platform == 'shodan':
            if 'port' in self.df:
                stats['ports'] = self.df['port'].value_counts().to_dict()
            if 'org' in self.df:
                stats['organizations'] = self.df['org'].value_counts().head(10).to_dict()
            if 'country_name' in self.df:
                stats['countries'] = self.df['country_name'].value_counts().head(10).to_dict()
        
        elif self.platform == 'censys':
            if 'services' in self.df:
                services = self.df['services'].explode()
                stats['services'] = services.value_counts().head(10).to_dict()
            if 'location' in self.df:
                stats['countries'] = self.df['location'].apply(lambda x: x.get('country')).value_counts().head(10).to_dict()

        return stats

    def generate_visualizations(self) -> Dict[str, go.Figure]:
        """Generate interactive visualizations of results"""
        if self.df is None:
            return {}

        figures = {}

        # Geographic distribution
        if self.platform == 'shodan' and 'country_name' in self.df:
            fig = px.choropleth(
                self.df['country_name'].value_counts().reset_index(),
                locations='index',
                locationmode='country names',
                color='country_name',
                title='Geographic Distribution of Results'
            )
            figures['geo_distribution'] = fig

        # Port distribution
        if 'port' in self.df:
            fig = px.bar(
                self.df['port'].value_counts().head(10).reset_index(),
                x='index',
                y='port',
                title='Top 10 Ports'
            )
            figures['port_distribution'] = fig

        return figures

    def export_results(self, format: str, filepath: str):
        """Export results to various formats"""
        if self.df is None:
            raise ValueError("No results loaded")

        if format == 'csv':
            self.df.to_csv(filepath, index=False)
        elif format == 'xlsx':
            self.df.to_excel(filepath, index=False)
        elif format == 'json':
            self.df.to_json(filepath, orient='records')
        else:
            raise ValueError(f"Unsupported export format: {format}")

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.init_api_manager()  # Inicializamos el api_manager antes de otras inicializaciones
        self.db_manager = DatabaseManager()
        self.query_builder = QueryBuilder()
        self.results_analyzer = ResultsAnalyzer()
        self.init_ui()
        self.setup_menu()
        self.load_settings()
        self.init_statusbar()
        self.search_worker = None

    def init_api_manager(self):
        """Initialize API manager with proper error handling"""
        try:
            # Cargar configuración
            config_path = Path(CONFIG_FILE)
            if not config_path.exists():
                # Crear el directorio si no existe
                config_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Configuración por defecto
                default_config = {
                    'api_keys': {
                        'shodan': '',
                        'censys_id': '',
                        'censys_secret': ''
                    }
                }
                
                # Guardar configuración por defecto
                with open(config_path, 'w') as f:
                    yaml.safe_dump(default_config, f)
                
                QMessageBox.warning(
                    self,
                    "Configuration Notice",
                    f"Default configuration file created at {CONFIG_FILE}\n"
                    "Please add your API keys before performing searches."
                )
                self.config = default_config
            else:
                # Cargar configuración existente
                with open(config_path) as f:
                    self.config = yaml.safe_load(f)

            # Verificar estructura de la configuración
            if 'api_keys' not in self.config:
                self.config['api_keys'] = {}
            
            # Obtener las API keys
            api_keys = {
                'shodan': self.config['api_keys'].get('shodan', ''),
                'censys_id': self.config['api_keys'].get('censys_id', ''),
                'censys_secret': self.config['api_keys'].get('censys_secret', '')
            }

            # Inicializar API manager
            self.api_manager = APIManager(api_keys)
            
            # Inicializar sesión asincrónicamente
            self.api_manager.loop.run_until_complete(self.api_manager.init_session())

        except Exception as e:
            logging.error(f"Error initializing API manager: {e}")
            QMessageBox.critical(
                self,
                "API Configuration Error",
                f"Failed to initialize API connections: {str(e)}\n"
                "The application will run with limited functionality."
            )
            # Crear un API manager con claves vacías
            self.api_manager = APIManager({
                'shodan': '',
                'censys_id': '',
                'censys_secret': ''
            })
        
    def load_config(self):
        """Load application configuration"""
        try:
            with open(CONFIG_FILE) as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            self.config = {}

    def init_api(self):
        """Initialize API connections"""
        api_keys = self.config.get('api_keys', {})
        try:
            self.api_manager = APIManager(api_keys)
        except Exception as e:
            logging.error(f"Error initializing APIs: {e}")
            QMessageBox.critical(self, "API Error", 
                               "Failed to initialize API connections. Please check your configuration.")

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle('Zhen Professional Search Toolkit')
        self.setMinimumSize(1400, 900)
        
        # Create main layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        
        # Create and add splitter for resizable panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Add sidebar
        self.sidebar = self.create_sidebar()
        splitter.addWidget(self.sidebar)
        
        # Add central area
        self.central_area = self.create_central_area()
        splitter.addWidget(self.central_area)
        
        # Add details panel
        self.details_panel = self.create_details_panel()
        splitter.addWidget(self.details_panel)
        
        # Set initial splitter sizes
        splitter.setSizes([200, 800, 400])
    def create_details_panel(self) -> QWidget:
        """Create the details panel that shows additional information"""
        details_panel = QWidget()
        layout = QVBoxLayout(details_panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget for different detail views
        self.details_tabs = QTabWidget()
        self.details_tabs.setDocumentMode(True)
        
        # Add detail tabs
        self.details_tabs.addTab(self.create_overview_tab(), "Overview")
        self.details_tabs.addTab(self.create_technical_tab(), "Technical")
        self.details_tabs.addTab(self.create_history_tab(), "History")
        self.details_tabs.addTab(self.create_notes_tab(), "Notes")
        
        layout.addWidget(self.details_tabs)
        return details_panel

    def create_overview_tab(self) -> QWidget:
        """Create the overview tab showing summary information"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Summary section
        summary_group = QGroupBox("Summary")
        summary_layout = QVBoxLayout()
        
        # Status indicator
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        summary_layout.addLayout(status_layout)
        
        # Quick stats
        stats_layout = QGridLayout()
        
        # Results count
        stats_layout.addWidget(QLabel("Total Results:"), 0, 0)
        self.results_count = QLabel("0")
        stats_layout.addWidget(self.results_count, 0, 1)
        
        # Last update
        stats_layout.addWidget(QLabel("Last Updated:"), 1, 0)
        self.last_update = QLabel("-")
        stats_layout.addWidget(self.last_update, 1, 1)
        
        # Query time
        stats_layout.addWidget(QLabel("Query Time:"), 2, 0)
        self.query_time = QLabel("-")
        stats_layout.addWidget(self.query_time, 2, 1)
        
        summary_layout.addLayout(stats_layout)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Tags section
        tags_group = QGroupBox("Tags")
        tags_layout = QVBoxLayout()
        self.tags_list = QListWidget()
        self.tags_list.setMaximumHeight(100)
        add_tag_layout = QHBoxLayout()
        self.new_tag_input = QLineEdit()
        self.new_tag_input.setPlaceholderText("Add new tag...")
        add_tag_btn = QPushButton("Add")
        add_tag_btn.clicked.connect(self.add_tag)
        add_tag_layout.addWidget(self.new_tag_input)
        add_tag_layout.addWidget(add_tag_btn)
        tags_layout.addWidget(self.tags_list)
        tags_layout.addLayout(add_tag_layout)
        tags_group.setLayout(tags_layout)
        layout.addWidget(tags_group)
        
        # Statistics section
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        self.stats_tree = QTreeWidget()
        self.stats_tree.setHeaderLabels(["Metric", "Value"])
        self.stats_tree.setAlternatingRowColors(True)
        stats_layout.addWidget(self.stats_tree)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        return tab
    def create_technical_tab(self) -> QWidget:
        """Create the technical tab showing detailed technical information"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Raw data viewer
        raw_group = QGroupBox("Raw Data")
        raw_layout = QVBoxLayout()
        self.raw_data_view = QTextEdit()
        self.raw_data_view.setReadOnly(True)
        self.raw_data_view.setFont(QFont("Courier New", 10))
        raw_layout.addWidget(self.raw_data_view)
        
        # Format controls
        format_layout = QHBoxLayout()
        self.format_selector = QComboBox()
        self.format_selector.addItems(["JSON", "YAML", "Text"])
        self.format_selector.currentTextChanged.connect(self.update_raw_data_format)
        format_layout.addWidget(QLabel("Format:"))
        format_layout.addWidget(self.format_selector)
        
        # Search in raw data
        search_layout = QHBoxLayout()
        self.raw_search = QLineEdit()
        self.raw_search.setPlaceholderText("Search in raw data...")
        self.raw_search.textChanged.connect(self.search_raw_data)
        search_layout.addWidget(self.raw_search)
        
        raw_layout.addLayout(format_layout)
        raw_layout.addLayout(search_layout)
        raw_group.setLayout(raw_layout)
        layout.addWidget(raw_group)
        
        # Technical details table
        details_group = QGroupBox("Technical Details")
        details_layout = QVBoxLayout()
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(2)
        self.details_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.details_table.horizontalHeader().setStretchLastSection(True)
        details_layout.addWidget(self.details_table)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        return tab

    def update_raw_data_format(self, format_type: str):
        """
        Actualiza el formato de visualización de los datos raw
        
        Args:
            format_type (str): Tipo de formato ('JSON', 'YAML', 'Text')
        """
        try:
            # Obtener los datos actuales
            current_data = self.raw_data_view.toPlainText()
            if not current_data:
                return
                
            # Intentar parsear los datos actuales
            try:
                if format_type != 'Text':
                    # Si los datos actuales están en JSON
                    if current_data.strip().startswith('{') or current_data.strip().startswith('['):
                        data = json.loads(current_data)
                    # Si los datos actuales están en YAML
                    else:
                        data = yaml.safe_load(current_data)
                else:
                    data = current_data
            except Exception:
                QMessageBox.warning(
                    self,
                    "Format Warning",
                    "Could not parse current data. Showing as plain text."
                )
                return
                
            # Formatear según el tipo seleccionado
            if format_type == 'JSON':
                formatted_data = json.dumps(data, indent=2, sort_keys=True)
                # Aplicar resaltado de sintaxis para JSON
                self.apply_json_highlighting(formatted_data)
            elif format_type == 'YAML':
                formatted_data = yaml.dump(data, sort_keys=True, allow_unicode=True)
                # Aplicar resaltado de sintaxis para YAML
                self.apply_yaml_highlighting(formatted_data)
            else:  # Text
                if isinstance(data, (dict, list)):
                    formatted_data = pprint.pformat(data)
                else:
                    formatted_data = str(data)
                # Limpiar cualquier formato previo
                self.raw_data_view.setPlainText(formatted_data)
                
            # Actualizar la vista
            cursor = self.raw_data_view.textCursor()
            current_position = cursor.position()
            self.raw_data_view.setPlainText(formatted_data)
            
            # Restaurar la posición del cursor
            cursor.setPosition(min(current_position, len(formatted_data)))
            self.raw_data_view.setTextCursor(cursor)
            
        except Exception as e:
            logging.error(f"Error updating raw data format: {e}")
            QMessageBox.critical(
                self,
                "Format Error",
                f"Failed to update data format: {str(e)}"
            )

    def search_raw_data(self, search_text: str):
        """
        Busca texto en los datos raw y resalta las coincidencias
        
        Args:
            search_text (str): Texto a buscar
        """
        try:
            # Limpiar resaltados previos
            self.clear_search_highlights()
            
            if not search_text.strip():
                return
                
            # Crear formato para resaltado
            highlight_format = QTextCharFormat()
            highlight_format.setBackground(QColor(255, 255, 0, 100))  # Amarillo semitransparente
            highlight_format.setForeground(QColor(0, 0, 0))  # Texto negro
            
            # Obtener el texto completo
            document = self.raw_data_view.document()
            
            # Preparar búsqueda
            find_cursor = QTextCursor(document)
            
            # Opciones de búsqueda
            regex = False
            case_sensitive = False
            whole_words = False
            
            # Si el texto comienza con '/' y termina con '/', tratarlo como regex
            if search_text.startswith('/') and search_text.endswith('/'):
                regex = True
                search_text = search_text[1:-1]
            # Si el texto está entre comillas, buscar palabras completas
            elif search_text.startswith('"') and search_text.endswith('"'):
                whole_words = True
                search_text = search_text[1:-1]
            # Si el texto tiene mayúsculas, hacer la búsqueda case sensitive
            elif any(c.isupper() for c in search_text):
                case_sensitive = True
            
            # Configurar las flags de búsqueda
            find_flags = QTextDocument.FindFlag(0)
            if case_sensitive:
                find_flags |= QTextDocument.FindFlag.FindCaseSensitively
            if whole_words:
                find_flags |= QTextDocument.FindFlag.FindWholeWords
            
            # Realizar la búsqueda
            matches = 0
            while True:
                if regex:
                    # Búsqueda con expresiones regulares
                    pattern = re.compile(search_text, re.IGNORECASE if not case_sensitive else 0)
                    block = find_cursor.block()
                    while block.isValid():
                        text = block.text()
                        for match in pattern.finditer(text):
                            cursor = QTextCursor(block)
                            cursor.setPosition(block.position() + match.start())
                            cursor.setPosition(block.position() + match.end(), QTextCursor.MoveMode.KeepAnchor)
                            cursor.mergeCharFormat(highlight_format)
                            matches += 1
                        block = block.next()
                    break
                else:
                    # Búsqueda normal
                    find_cursor = document.find(search_text, find_cursor, find_flags)
                    if find_cursor.isNull():
                        break
                    find_cursor.mergeCharFormat(highlight_format)
                    matches += 1
            
            # Actualizar la barra de estado con el número de coincidencias
            self.statusBar().showMessage(f"Found {matches} match{'es' if matches != 1 else ''}")
            
            # Si hay coincidencias, seleccionar la primera
            if matches > 0:
                cursor = QTextCursor(document)
                cursor = document.find(search_text, cursor, find_flags)
                if not cursor.isNull():
                    self.raw_data_view.setTextCursor(cursor)
                    self.raw_data_view.ensureCursorVisible()
            
        except Exception as e:
            logging.error(f"Error searching raw data: {e}")
            self.statusBar().showMessage(f"Search error: {str(e)}")

    def clear_search_highlights(self):
        """Limpia los resaltados de búsqueda anteriores"""
        try:
            # Crear formato sin resaltado
            normal_format = QTextCharFormat()
            normal_format.setBackground(QColor("white"))
            
            # Aplicar a todo el documento
            cursor = QTextCursor(self.raw_data_view.document())
            cursor.select(QTextCursor.SelectionType.Document)
            cursor.mergeCharFormat(normal_format)
            
        except Exception as e:
            logging.error(f"Error clearing search highlights: {e}")

    def apply_json_highlighting(self, text: str):
        """
        Aplica resaltado de sintaxis para JSON
        
        Args:
            text (str): Texto JSON a resaltar
        """
        try:
            # Crear formatos para diferentes elementos
            string_format = QTextCharFormat()
            string_format.setForeground(QColor("#008000"))  # Verde
            
            number_format = QTextCharFormat()
            number_format.setForeground(QColor("#0000FF"))  # Azul
            
            keyword_format = QTextCharFormat()
            keyword_format.setForeground(QColor("#FF0000"))  # Rojo
            
            # Establecer el texto
            self.raw_data_view.setPlainText(text)
            
            # Aplicar resaltado
            document = self.raw_data_view.document()
            
            # Patrones para resaltado
            patterns = {
                'string': r'"[^"\\]*(?:\\.[^"\\]*)*"',
                'number': r'\b-?\d+\.?\d*\b',
                'keyword': r'\b(true|false|null)\b'
            }
            
            for pattern_type, pattern in patterns.items():
                format_to_use = {
                    'string': string_format,
                    'number': number_format,
                    'keyword': keyword_format
                }[pattern_type]
                
                cursor = QTextCursor(document)
                regex = QRegularExpression(pattern)
                
                while True:
                    match = regex.match(document.toPlainText(), cursor.position())
                    if not match.hasMatch():
                        break
                        
                    cursor.setPosition(match.capturedStart())
                    cursor.setPosition(match.capturedEnd(), QTextCursor.MoveMode.KeepAnchor)
                    cursor.mergeCharFormat(format_to_use)
                    cursor.setPosition(match.capturedEnd())
                    
        except Exception as e:
            logging.error(f"Error applying JSON highlighting: {e}")

    def apply_yaml_highlighting(self, text: str):
        """
        Aplica resaltado de sintaxis para YAML
        
        Args:
            text (str): Texto YAML a resaltar
        """
        try:
            # Crear formatos para diferentes elementos
            key_format = QTextCharFormat()
            key_format.setForeground(QColor("#800080"))  # Púrpura
            
            value_format = QTextCharFormat()
            value_format.setForeground(QColor("#008000"))  # Verde
            
            list_format = QTextCharFormat()
            list_format.setForeground(QColor("#0000FF"))  # Azul
            
            # Establecer el texto
            self.raw_data_view.setPlainText(text)
            
            # Aplicar resaltado
            document = self.raw_data_view.document()
            
            # Patrones para resaltado
            patterns = {
                'key': r'^[^:]+(?=:)',
                'value': r'(?<=:)\s*.+$',
                'list': r'^\s*-\s+'
            }
            
            for pattern_type, pattern in patterns.items():
                format_to_use = {
                    'key': key_format,
                    'value': value_format,
                    'list': list_format
                }[pattern_type]
                
                cursor = QTextCursor(document)
                regex = QRegularExpression(pattern)
                
                while True:
                    match = regex.match(document.toPlainText(), cursor.position())
                    if not match.hasMatch():
                        break
                        
                    cursor.setPosition(match.capturedStart())
                    cursor.setPosition(match.capturedEnd(), QTextCursor.MoveMode.KeepAnchor)
                    cursor.mergeCharFormat(format_to_use)
                    cursor.setPosition(match.capturedEnd())
                    
        except Exception as e:
            logging.error(f"Error applying YAML highlighting: {e}")

    def create_history_tab(self) -> QWidget:
        """Create the history tab showing historical information"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Timeline view
        timeline_group = QGroupBox("Timeline")
        timeline_layout = QVBoxLayout()
        self.timeline_view = QListWidget()
        self.timeline_view.setAlternatingRowColors(True)
        timeline_layout.addWidget(self.timeline_view)
        timeline_group.setLayout(timeline_layout)
        layout.addWidget(timeline_group)
        
        # Historical data
        history_group = QGroupBox("Historical Data")
        history_layout = QVBoxLayout()
        
        # Date range selector
        date_layout = QHBoxLayout()
        date_layout.addWidget(QLabel("Date Range:"))
        self.date_range = QComboBox()
        self.date_range.addItems([
            "Last 24 Hours", "Last Week", "Last Month",
            "Last 3 Months", "Last Year", "All Time"
        ])
        self.date_range.currentTextChanged.connect(self.update_history_range)
        date_layout.addWidget(self.date_range)
        history_layout.addLayout(date_layout)
        
        # Historical stats table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels([
            "Date", "Results", "Changes", "Query Time"
        ])
        history_layout.addWidget(self.history_table)
        
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        return tab

    def update_history_range(self, range_text: str):
        """
        Actualiza la vista del historial basado en el rango de fechas seleccionado
        
        Args:
            range_text (str): Texto del rango seleccionado (ej: "Last 24 Hours", "Last Week", etc.)
        """
        try:
            # Calcular fechas basadas en el rango seleccionado
            start_date, end_date = self.calculate_date_range(range_text)
            
            # Obtener datos históricos
            historical_data = self.get_historical_data(start_date, end_date)
            
            # Actualizar la tabla de historia
            self.update_history_table(historical_data)
            
            # Actualizar la línea de tiempo
            self.update_timeline(historical_data)
            
            # Actualizar estadísticas comparativas
            self.update_comparative_stats(historical_data)
            
        except Exception as e:
            logging.error(f"Error updating history range: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update history: {str(e)}")

    def calculate_date_range(self, range_text: str) -> tuple[datetime.datetime, datetime.datetime]:
        """
        Calcula las fechas de inicio y fin basadas en el rango seleccionado
        
        Args:
            range_text (str): Texto del rango seleccionado
            
        Returns:
            tuple[datetime, datetime]: Fechas de inicio y fin
        """
        end_date = datetime.datetime.now()
        
        if range_text == "Last 24 Hours":
            start_date = end_date - datetime.timedelta(days=1)
        elif range_text == "Last Week":
            start_date = end_date - datetime.timedelta(weeks=1)
        elif range_text == "Last Month":
            start_date = end_date - datetime.timedelta(days=30)
        elif range_text == "Last 3 Months":
            start_date = end_date - datetime.timedelta(days=90)
        elif range_text == "Last Year":
            start_date = end_date - datetime.timedelta(days=365)
        else:  # All Time
            start_date = datetime.datetime(2000, 1, 1)  # Fecha arbitraria en el pasado
            
        return start_date, end_date

    def get_historical_data(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[Dict]:
        """
        Obtiene datos históricos de la base de datos para el rango especificado
        
        Args:
            start_date (datetime): Fecha de inicio
            end_date (datetime): Fecha de fin
            
        Returns:
            List[Dict]: Lista de registros históricos
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        r.*, 
                        q.query,
                        q.platform,
                        q.name as query_name
                    FROM results r
                    JOIN queries q ON r.query_id = q.id 
                    WHERE r.timestamp BETWEEN ? AND ?
                    ORDER BY r.timestamp DESC
                """, (start_date, end_date))
                
                results = []
                for row in cursor.fetchall():
                    result_data = dict(row)
                    
                    # Parsear JSON almacenado
                    try:
                        result_data['results_json'] = json.loads(result_data['results_json'])
                        result_data['metadata_json'] = json.loads(result_data['metadata_json'])
                    except (json.JSONDecodeError, TypeError):
                        result_data['results_json'] = {}
                        result_data['metadata_json'] = {}
                    
                    results.append(result_data)
                    
                return results
                
        except Exception as e:
            logging.error(f"Error getting historical data: {e}")
            raise

    def update_history_table(self, historical_data: List[Dict]):
        """
        Actualiza la tabla de historia con los datos proporcionados
        
        Args:
            historical_data (List[Dict]): Lista de registros históricos
        """
        try:
            # Limpiar tabla
            self.history_table.setRowCount(0)
            
            # Configurar columnas si es necesario
            if self.history_table.columnCount() != 4:
                self.history_table.setColumnCount(4)
                self.history_table.setHorizontalHeaderLabels([
                    "Date", "Results", "Changes", "Query Time"
                ])
            
            # Agregar datos
            for row_idx, record in enumerate(historical_data):
                self.history_table.insertRow(row_idx)
                
                # Fecha
                timestamp = datetime.datetime.fromisoformat(record['timestamp'])
                date_item = QTableWidgetItem(timestamp.strftime('%Y-%m-%d %H:%M:%S'))
                self.history_table.setItem(row_idx, 0, date_item)
                
                # Resultados
                results_count = len(record['results_json'])
                results_item = QTableWidgetItem(str(results_count))
                self.history_table.setItem(row_idx, 1, results_item)
                
                # Cambios (comparar con registro anterior)
                if row_idx < len(historical_data) - 1:
                    prev_count = len(historical_data[row_idx + 1]['results_json'])
                    change = results_count - prev_count
                    change_text = f"{'+' if change > 0 else ''}{change}"
                    change_item = QTableWidgetItem(change_text)
                    
                    # Colorear según el cambio
                    if change > 0:
                        change_item.setForeground(QColor('#28a745'))  # Verde
                    elif change < 0:
                        change_item.setForeground(QColor('#dc3545'))  # Rojo
                else:
                    change_item = QTableWidgetItem("-")
                self.history_table.setItem(row_idx, 2, change_item)
                
                # Tiempo de query
                query_time = record['execution_time']
                time_item = QTableWidgetItem(f"{query_time:.2f}s")
                self.history_table.setItem(row_idx, 3, time_item)
                
                # Guardar datos completos en el primer item de la fila
                date_item.setData(Qt.ItemDataRole.UserRole, record)
                
            # Ajustar columnas
            self.history_table.resizeColumnsToContents()
            
        except Exception as e:
            logging.error(f"Error updating history table: {e}")
            raise

    def update_timeline(self, historical_data: List[Dict]):
        """
        Actualiza la vista de línea de tiempo con los eventos históricos
        
        Args:
            historical_data (List[Dict]): Lista de registros históricos
        """
        try:
            self.timeline_view.clear()
            
            for record in historical_data:
                timestamp = datetime.datetime.fromisoformat(record['timestamp'])
                
                # Crear item con formato
                item_text = (
                    f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"{record['query_name']} ({record['platform']})\n"
                    f"Results: {len(record['results_json'])} | "
                    f"Time: {record['execution_time']:.2f}s"
                )
                
                item = QListWidgetItem(item_text)
                
                # Establecer tooltip con detalles adicionales
                tooltip = (
                    f"Query: {record['query']}\n"
                    f"Status: {'Success' if record['success'] else 'Failed'}\n"
                    f"Platform: {record['platform']}\n"
                    f"Total Results: {len(record['results_json'])}"
                )
                item.setToolTip(tooltip)
                
                # Guardar datos completos
                item.setData(Qt.ItemDataRole.UserRole, record)
                
                # Establecer icono según el estado
                if record['success']:
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
                else:
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
                
                self.timeline_view.addItem(item)
                
        except Exception as e:
            logging.error(f"Error updating timeline: {e}")
            raise

    def update_comparative_stats(self, historical_data: List[Dict]):
        """
        Actualiza las estadísticas comparativas basadas en los datos históricos
        
        Args:
            historical_data (List[Dict]): Lista de registros históricos
        """
        try:
            if not historical_data:
                return
                
            # Calcular estadísticas
            stats = {
                'total_searches': len(historical_data),
                'total_results': sum(len(r['results_json']) for r in historical_data),
                'avg_results': sum(len(r['results_json']) for r in historical_data) / len(historical_data),
                'avg_time': sum(r['execution_time'] for r in historical_data) / len(historical_data),
                'success_rate': sum(1 for r in historical_data if r['success']) / len(historical_data) * 100,
                'platforms': {}
            }
            
            # Estadísticas por plataforma
            for record in historical_data:
                platform = record['platform']
                if platform not in stats['platforms']:
                    stats['platforms'][platform] = {
                        'count': 0,
                        'total_results': 0,
                        'total_time': 0
                    }
                
                stats['platforms'][platform]['count'] += 1
                stats['platforms'][platform]['total_results'] += len(record['results_json'])
                stats['platforms'][platform]['total_time'] += record['execution_time']
            
            # Calcular promedios por plataforma
            for platform in stats['platforms']:
                platform_stats = stats['platforms'][platform]
                platform_stats['avg_results'] = platform_stats['total_results'] / platform_stats['count']
                platform_stats['avg_time'] = platform_stats['total_time'] / platform_stats['count']
            
            # Actualizar árbol de estadísticas
            self.stats_tree.clear()
            
            # Agregar estadísticas generales
            general_item = QTreeWidgetItem(["General Statistics"])
            self.stats_tree.addTopLevelItem(general_item)
            
            general_stats = [
                ("Total Searches", f"{stats['total_searches']:,}"),
                ("Total Results", f"{stats['total_results']:,}"),
                ("Average Results", f"{stats['avg_results']:.2f}"),
                ("Average Time", f"{stats['avg_time']:.2f}s"),
                ("Success Rate", f"{stats['success_rate']:.1f}%")
            ]
            
            for label, value in general_stats:
                stat_item = QTreeWidgetItem([label, value])
                general_item.addChild(stat_item)
            
            # Agregar estadísticas por plataforma
            for platform, platform_stats in stats['platforms'].items():
                platform_item = QTreeWidgetItem([f"{platform} Statistics"])
                self.stats_tree.addTopLevelItem(platform_item)
                
                platform_details = [
                    ("Searches", f"{platform_stats['count']:,}"),
                    ("Total Results", f"{platform_stats['total_results']:,}"),
                    ("Average Results", f"{platform_stats['avg_results']:.2f}"),
                    ("Average Time", f"{platform_stats['avg_time']:.2f}s")
                ]
                
                for label, value in platform_details:
                    stat_item = QTreeWidgetItem([label, value])
                    platform_item.addChild(stat_item)
            
            # Expandir todos los items
            self.stats_tree.expandAll()
            
        except Exception as e:
            logging.error(f"Error updating comparative stats: {e}")
            raise

    def create_notes_tab(self) -> QWidget:
        """Create the notes tab for user annotations"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Notes editor
        notes_group = QGroupBox("Notes")
        notes_layout = QVBoxLayout()
        self.notes_editor = QTextEdit()
        notes_layout.addWidget(self.notes_editor)
        
        # Notes toolbar
        toolbar_layout = QHBoxLayout()
        save_note_btn = QPushButton("Save")
        save_note_btn.clicked.connect(self.save_notes)
        clear_note_btn = QPushButton("Clear")
        clear_note_btn.clicked.connect(self.clear_notes)
        toolbar_layout.addWidget(save_note_btn)
        toolbar_layout.addWidget(clear_note_btn)
        notes_layout.addLayout(toolbar_layout)
        
        notes_group.setLayout(notes_layout)
        layout.addWidget(notes_group)
        
        # Tagged items
        tagged_group = QGroupBox("Tagged Items")
        tagged_layout = QVBoxLayout()
        self.tagged_list = QListWidget()
        tagged_layout.addWidget(self.tagged_list)
        tagged_group.setLayout(tagged_layout)
        layout.addWidget(tagged_group)
        
        return tab

    def update_details(self, data: Union[Dict, None]):
        """Update the details panel with new data"""
        if data is None:
            self.clear_details()
            return
            
        try:
            # Update overview tab
            self.update_overview(data)
            
            # Update technical tab
            self.update_technical(data)
            
            # Update history
            self.update_history(data)
            
            # Load associated notes
            self.load_notes(data)
            
        except Exception as e:
            logging.error(f"Error updating details: {e}")
            self.statusBar().showMessage(f"Error updating details: {str(e)}")

    def update_overview(self, data: Dict):
        """Update the overview tab with new data"""
        try:
            # Update status
            status = data.get('status', 'Unknown')
            self.status_label.setText(status)
            self.status_label.setStyleSheet(f"color: {self.get_status_color(status)}")
            
            # Update quick stats
            self.results_count.setText(str(data.get('total_results', 0)))
            self.last_update.setText(data.get('last_update', '-'))
            self.query_time.setText(f"{data.get('query_time', 0):.2f}s")
            
            # Update tags
            self.update_tags(data.get('tags', []))
            
            # Update statistics tree
            self.update_statistics_tree(data.get('statistics', {}))
            
        except Exception as e:
            logging.error(f"Error updating overview: {e}")
            raise
    def update_statistics_tree(self, statistics: Dict):
        """Update the statistics tree with new data"""
        try:
            self.stats_tree.clear()
            
            for category, stats in statistics.items():
                # Crear item principal para la categoría
                category_item = QTreeWidgetItem([category, ""])
                self.stats_tree.addTopLevelItem(category_item)
                
                if isinstance(stats, dict):
                    # Agregar sub-items para cada estadística
                    for key, value in stats.items():
                        stat_item = QTreeWidgetItem([key, str(value)])
                        category_item.addChild(stat_item)
                else:
                    # Si no es un diccionario, mostrar el valor directamente
                    category_item.setText(1, str(stats))
                    
            # Expandir todos los items
            self.stats_tree.expandAll()
            
        except Exception as e:
            logging.error(f"Error updating statistics tree: {e}")
            raise
    def update_technical(self, data: Dict):
        """Update the technical tab with new data"""
        try:
            # Update raw data view
            self.update_raw_data(data)
            
            # Update technical details table
            self.update_details_table(data)
            
        except Exception as e:
            logging.error(f"Error updating technical details: {e}")
            raise

    def update_history(self, data: Dict):
        """Update the history tab with historical data"""
        try:
            # Clear existing timeline
            self.timeline_view.clear()
            
            # Add history events
            for event in data.get('history', []):
                item = QListWidgetItem(
                    f"{event['timestamp']} - {event['description']}"
                )
                item.setData(Qt.ItemDataRole.UserRole, event)
                self.timeline_view.addItem(item)
            
            # Update historical data table
            self.update_history_table(data.get('historical_data', []))
            
        except Exception as e:
            logging.error(f"Error updating history: {e}")
            raise

    def add_tag(self):
        """Add a new tag to the current item"""
        try:
            new_tag = self.new_tag_input.text().strip()
            if not new_tag:
                return
                
            # Add to database
            current_id = self.get_current_item_id()
            if current_id:
                self.db_manager.add_tag(current_id, new_tag)
                
                # Add to UI
                self.tags_list.addItem(new_tag)
                self.new_tag_input.clear()
                
        except Exception as e:
            logging.error(f"Error adding tag: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add tag: {str(e)}")

    def save_notes(self):
        """Save the current notes"""
        try:
            current_id = self.get_current_item_id()
            if current_id:
                notes = self.notes_editor.toPlainText()
                self.db_manager.save_notes(current_id, notes)
                self.statusBar().showMessage("Notes saved successfully")
                
        except Exception as e:
            logging.error(f"Error saving notes: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save notes: {str(e)}")

    def clear_notes(self):
        """Clear the notes editor"""
        reply = QMessageBox.question(
            self,
            "Clear Notes",
            "Are you sure you want to clear all notes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.notes_editor.clear()
            self.save_notes()

    def get_status_color(self, status: str) -> str:
        """Get color for status indicator"""
        colors = {
            'Active': '#28a745',
            'Pending': '#ffc107',
            'Error': '#dc3545',
            'Complete': '#17a2b8',
            'Unknown': '#6c757d'
        }
        return colors.get(status, '#6c757d')
    def create_sidebar(self):
        """Create the sidebar panel"""
        sidebar = QWidget()
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Search input
        search_layout = QVBoxLayout()
        search_label = QLabel("Quick Search")
        search_label.setObjectName("sidebarLabel")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search terms...")
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Favorites
        favorites_group = QGroupBox("Favorites")
        favorites_layout = QVBoxLayout(favorites_group)
        self.favorites_list = QListWidget()
        self.favorites_list.itemDoubleClicked.connect(self.load_favorite)
        favorites_layout.addWidget(self.favorites_list)
        layout.addWidget(favorites_group)
        
        # Recent searches
        recent_group = QGroupBox("Recent Searches")
        recent_layout = QVBoxLayout(recent_group)
        self.recent_list = QListWidget()
        self.recent_list.itemDoubleClicked.connect(self.load_recent)
        recent_layout.addWidget(self.recent_list)
        layout.addWidget(recent_group)
        
        # Load favorites and recent searches
        self.load_favorites()
        self.load_recent_searches()
        
        return sidebar
    def load_recent_searches(self):
        """Load recent searches into sidebar"""
        try:
            recent = self.db_manager.get_recent_queries()
            self.recent_list.clear()
            
            for query in recent:
                item = QListWidgetItem(query['name'])
                item.setData(Qt.ItemDataRole.UserRole, query)
                self.recent_list.addItem(item)
                
        except Exception as e:
            logging.error(f"Error loading recent searches: {e}")
            QMessageBox.warning(self, "Error", "Could not load recent searches")
    
    def load_favorites(self):
        """Load favorite queries into sidebar"""
        try:
            favorites = self.db_manager.get_favorite_queries()
            self.favorites_list.clear()
            
            for fav in favorites:
                item = QListWidgetItem(fav['name'])
                item.setData(Qt.ItemDataRole.UserRole, fav)
                self.favorites_list.addItem(item)
                
        except Exception as e:
            logging.error(f"Error loading favorites: {e}")
            QMessageBox.warning(self, "Error", "Could not load favorites")
    
    def load_favorite(self, item):
        """Load a favorite search query"""
        try:
            # Get query data from item
            query_data = item.data(Qt.ItemDataRole.UserRole)
            if query_data:
                # Load query into UI
                self.load_query(query_data)
        except Exception as e:
            logging.error(f"Error loading favorite: {e}")
            QMessageBox.warning(self, "Error", f"Could not load favorite: {str(e)}")
    def parse_query_to_fields(self, query):
        """Parse a query string and populate form fields"""
        try:
            # Split query into parts
            parts = query.split(' AND ')
            
            for part in parts:
                # Remove parentheses
                part = part.strip('()')
                
                # Try to match part to a field
                for category, section in self.query_sections.items():
                    for field_layout in section.findChildren(QHBoxLayout):
                        label = field_layout.itemAt(0).widget()
                        input_field = field_layout.itemAt(1).widget()
                        
                        field_name = label.text().lower()
                        if field_name in part.lower():
                            # Extract value and set in field
                            value = part.split(':')[-1].strip('" ')
                            input_field.setText(value)
                            
        except Exception as e:
            logging.error(f"Error parsing query: {e}")    

    def load_query(self, query_data):
        """Load a query into the UI"""
        try:
            # Set platform
            if query_data.get('platform') == 'shodan':
                self.shodan_radio.setChecked(True)
            else:
                self.censys_radio.setChecked(True)
                
            # Parse and set query parameters
            query = query_data.get('query', '')
            self.query_preview.setText(query)
            
            # Clear existing inputs
            self.clear_search_form()
            
            # Try to parse query into form fields
            self.parse_query_to_fields(query)
            
        except Exception as e:
            logging.error(f"Error loading query: {e}")
            QMessageBox.warning(self, "Error", f"Could not load query: {str(e)}")
    def clear_search_form(self):
        """Clear all search form inputs"""
        for category, section in self.query_sections.items():
            for field_layout in section.findChildren(QHBoxLayout):
                input_field = field_layout.itemAt(1).widget()
                input_field.clear()
        
        self.query_preview.clear()
    def load_recent(self, item):
        """Load a recent search query"""
        try:
            # Get query data from item
            query_data = item.data(Qt.ItemDataRole.UserRole)
            if query_data:
                # Load query into UI
                self.load_query(query_data)
        except Exception as e:
            logging.error(f"Error loading recent search: {e}")
            QMessageBox.warning(self, "Error", f"Could not load recent search: {str(e)}")

    def create_central_area(self):
        """Create the central area with tabs"""
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        
        # Add tabs
        self.tabs.addTab(self.create_search_tab(), "Search")
        self.tabs.addTab(self.create_templates_tab(), "Templates")
        self.tabs.addTab(self.create_automation_tab(), "Automation")
        self.tabs.addTab(self.create_analysis_tab(), "Analysis")
        
        layout.addWidget(self.tabs)
        return central

    def create_search_tab(self):
        """Create the main search tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Platform selection
        platform_group = QGroupBox("Platform")
        platform_layout = QHBoxLayout()
        self.shodan_radio = QRadioButton("Shodan")
        self.censys_radio = QRadioButton("Censys")
        self.shodan_radio.setChecked(True)
        platform_layout.addWidget(self.shodan_radio)
        platform_layout.addWidget(self.censys_radio)
        platform_group.setLayout(platform_layout)
        layout.addWidget(platform_group)
        
        # Query builder
        builder_scroll = QScrollArea()
        builder_scroll.setWidgetResizable(True)
        builder_widget = QWidget()
        builder_layout = QVBoxLayout(builder_widget)
        
        # Add query builder categories
        self.query_sections = {}
        categories = ["Network", "Services", "Vulnerabilities", "Certificates", "Custom"]
        for category in categories:
            section = self.create_query_section(category)
            self.query_sections[category] = section
            builder_layout.addWidget(section)
        
        builder_scroll.setWidget(builder_widget)
        layout.addWidget(builder_scroll)
        
        # Query preview
        preview_group = QGroupBox("Query Preview")
        preview_layout = QVBoxLayout()
        self.query_preview = QTextEdit()
        self.query_preview.setReadOnly(True)
        preview_layout.addWidget(self.query_preview)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Search controls
        controls_layout = QHBoxLayout()
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.execute_search)
        self.save_query_button = QPushButton("Save Query")
        self.save_query_button.clicked.connect(self.save_current_query)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_search_form)
        
        controls_layout.addWidget(self.search_button)
        controls_layout.addWidget(self.save_query_button)
        controls_layout.addWidget(self.clear_button)
        layout.addLayout(controls_layout)
        
        return tab
    def save_current_query(self):
        """Save the current query"""
        try:
            query = self.query_preview.toPlainText()
            if not query:
                QMessageBox.warning(self, "Warning", "No query to save")
                return
                
            name, ok = QInputDialog.getText(self, "Save Query", "Enter a name for this query:")
            if ok and name:
                platform = 'shodan' if self.shodan_radio.isChecked() else 'censys'
                self.db_manager.add_query(
                    name=name,
                    platform=platform,
                    query=query,
                    favorite=True
                )
                self.load_favorites()
                QMessageBox.information(self, "Success", "Query saved successfully")
                
        except Exception as e:
            logging.error(f"Error saving query: {e}")
            QMessageBox.warning(self, "Error", f"Could not save query: {str(e)}")

    def create_query_section(self, category: str) -> QGroupBox:
        """Create a collapsible section for query building"""
        section = QGroupBox(category)
        layout = QVBoxLayout()
        
        fields = self.get_category_fields(category)
        field_widgets = {}
        
        for field in fields:
            field_layout = QHBoxLayout()
            label = QLabel(field)
            input_field = QLineEdit()
            input_field.textChanged.connect(self.update_query_preview)
            field_layout.addWidget(label)
            field_layout.addWidget(input_field)
            layout.addLayout(field_layout)
            field_widgets[field] = input_field
        
        section.setLayout(layout)
        return section
    def init_statusbar(self):
        """Initialize the status bar"""
        self.statusBar().showMessage("Ready")

    def create_templates_tab(self) -> QWidget:
        """Create the templates management tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Split view for templates
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Template categories list
        categories_group = QGroupBox("Categories")
        categories_layout = QVBoxLayout(categories_group)
        self.template_categories = QListWidget()
        categories_layout.addWidget(self.template_categories)
        
        # Add default categories
        default_categories = ["Network Scanning", "Vulnerability Detection", 
                            "Service Discovery", "SSL/TLS Analysis", "Custom"]
        self.template_categories.addItems(default_categories)
        
        # Template list
        templates_group = QGroupBox("Templates")
        templates_layout = QVBoxLayout(templates_group)
        self.templates_list = QListWidget()
        templates_layout.addWidget(self.templates_list)
        
        # Add to splitter
        splitter.addWidget(categories_group)
        splitter.addWidget(templates_group)
        
        # Template details and editor
        editor_group = QGroupBox("Template Editor")
        editor_layout = QGridLayout()
        
        # Template basic info
        editor_layout.addWidget(QLabel("Name:"), 0, 0)
        self.template_name = QLineEdit()
        editor_layout.addWidget(self.template_name, 0, 1)
        
        editor_layout.addWidget(QLabel("Platform:"), 1, 0)
        self.template_platform = QComboBox()
        self.template_platform.addItems(["Shodan", "Censys"])
        editor_layout.addWidget(self.template_platform, 1, 1)
        
        editor_layout.addWidget(QLabel("Category:"), 2, 0)
        self.template_category = QComboBox()
        self.template_category.addItems(default_categories)
        editor_layout.addWidget(self.template_category, 2, 1)
        
        # Template content
        editor_layout.addWidget(QLabel("Query Template:"), 3, 0)
        self.template_content = QTextEdit()
        editor_layout.addWidget(self.template_content, 3, 1)
        
        editor_layout.addWidget(QLabel("Parameters:"), 4, 0)
        self.template_params = QTextEdit()
        self.template_params.setPlaceholderText("Enter parameters in YAML format")
        editor_layout.addWidget(self.template_params, 4, 1)
        
        editor_layout.addWidget(QLabel("Description:"), 5, 0)
        self.template_description = QTextEdit()
        editor_layout.addWidget(self.template_description, 5, 1)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.save_template_btn = QPushButton("Save Template")
        self.save_template_btn.clicked.connect(self.save_template)
        self.delete_template_btn = QPushButton("Delete Template")
        self.delete_template_btn.clicked.connect(self.delete_template)
        self.test_template_btn = QPushButton("Test Template")
        self.test_template_btn.clicked.connect(self.test_template)
        
        button_layout.addWidget(self.save_template_btn)
        button_layout.addWidget(self.delete_template_btn)
        button_layout.addWidget(self.test_template_btn)
        
        editor_layout.addLayout(button_layout, 6, 1)
        
        editor_group.setLayout(editor_layout)
        layout.addWidget(editor_group)
        
        # Connect signals
        self.template_categories.itemClicked.connect(self.load_category_templates)
        self.templates_list.itemClicked.connect(self.load_template_details)
        
        return tab

    def create_automation_tab(self) -> QWidget:
        """Create the automation management tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Saved searches list
        searches_group = QGroupBox("Saved Searches")
        searches_layout = QVBoxLayout(searches_group)
        
        # Search filter
        filter_layout = QHBoxLayout()
        self.automation_search = QLineEdit()
        self.automation_search.setPlaceholderText("Filter saved searches...")
        filter_layout.addWidget(self.automation_search)
        searches_layout.addLayout(filter_layout)
        
        # Searches list
        self.automation_list = QListWidget()
        searches_layout.addWidget(self.automation_list)
        splitter.addWidget(searches_group)
        
        # Automation settings
        settings_group = QGroupBox("Automation Settings")
        settings_layout = QGridLayout()
        
        # Basic settings
        settings_layout.addWidget(QLabel("Name:"), 0, 0)
        self.automation_name = QLineEdit()
        settings_layout.addWidget(self.automation_name, 0, 1)
        
        settings_layout.addWidget(QLabel("Schedule:"), 1, 0)
        schedule_layout = QHBoxLayout()
        self.schedule_type = QComboBox()
        self.schedule_type.addItems(["Daily", "Weekly", "Monthly", "Custom"])
        schedule_layout.addWidget(self.schedule_type)
        self.schedule_value = QSpinBox()
        schedule_layout.addWidget(self.schedule_value)
        settings_layout.addLayout(schedule_layout, 1, 1)
        
        # Notification settings
        settings_layout.addWidget(QLabel("Notifications:"), 2, 0)
        self.notify_email = QLineEdit()
        self.notify_email.setPlaceholderText("Email address for notifications")
        settings_layout.addWidget(self.notify_email, 2, 1)
        
        # Export settings
        settings_layout.addWidget(QLabel("Auto Export:"), 3, 0)
        export_layout = QHBoxLayout()
        self.export_enabled = QCheckBox("Enable")
        self.export_format = QComboBox()
        self.export_format.addItems(["CSV", "JSON", "Excel"])
        export_layout.addWidget(self.export_enabled)
        export_layout.addWidget(self.export_format)
        settings_layout.addLayout(export_layout, 3, 1)
        
        # Action settings
        settings_layout.addWidget(QLabel("Actions:"), 4, 0)
        self.automation_actions = QListWidget()
        settings_layout.addWidget(self.automation_actions, 4, 1)
        
        # Add action button
        self.add_action_btn = QPushButton("Add Action")
        self.add_action_btn.clicked.connect(self.add_automation_action)
        settings_layout.addWidget(self.add_action_btn, 5, 1)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.save_automation_btn = QPushButton("Save")
        self.save_automation_btn.clicked.connect(self.save_automation)
        self.delete_automation_btn = QPushButton("Delete")
        self.delete_automation_btn.clicked.connect(self.delete_automation)
        self.run_now_btn = QPushButton("Run Now")
        self.run_now_btn.clicked.connect(self.run_automation)
        
        button_layout.addWidget(self.save_automation_btn)
        button_layout.addWidget(self.delete_automation_btn)
        button_layout.addWidget(self.run_now_btn)
        
        settings_layout.addLayout(button_layout, 6, 1)
        
        settings_group.setLayout(settings_layout)
        splitter.addWidget(settings_group)
        
        # Connect signals
        self.automation_search.textChanged.connect(self.filter_automations)
        self.automation_list.itemClicked.connect(self.load_automation)
        
        return tab

    def add_automation_action(self):
        """Add a new automation action"""
        try:
            # Show dialog to configure action
            action_types = ["Export Results", "Send Email", "Execute Script", "Generate Report"]
            action_type, ok = QInputDialog.getItem(
                self, 
                "Add Action",
                "Select action type:",
                action_types,
                0,
                False
            )
            
            if ok and action_type:
                # Create action configuration widget
                action_item = QListWidgetItem(action_type)
                action_config = {
                    'type': action_type,
                    'enabled': True,
                    'config': {}
                }
                
                # Configure specific action parameters
                if action_type == "Export Results":
                    action_config['config']['format'] = 'csv'
                    action_config['config']['path'] = f"{EXPORT_DIR}/auto_export"
                elif action_type == "Send Email":
                    action_config['config']['recipient'] = self.notify_email.text()
                    action_config['config']['subject'] = "Search Results"
                elif action_type == "Execute Script":
                    script_path, _ = QFileDialog.getOpenFileName(
                        self,
                        "Select Script",
                        "",
                        "Python Files (*.py)"
                    )
                    if script_path:
                        action_config['config']['script_path'] = script_path
                elif action_type == "Generate Report":
                    action_config['config']['template'] = "default_report"
                    action_config['config']['format'] = 'pdf'
                
                action_item.setData(Qt.ItemDataRole.UserRole, action_config)
                self.automation_actions.addItem(action_item)
                
        except Exception as e:
            logging.error(f"Error adding automation action: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add action: {str(e)}")
    def filter_automations(self, text: str):
        """
        Filtra la lista de automatizaciones según el texto ingresado
        
        Args:
            text (str): Texto para filtrar las automatizaciones
        """
        try:
            text = text.lower().strip()
            
            # Obtener todas las automatizaciones
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        saved_searches.*, 
                        queries.name as query_name,
                        queries.platform
                    FROM saved_searches
                    LEFT JOIN queries ON saved_searches.query_id = queries.id
                    ORDER BY saved_searches.name
                """)
                automations = [dict(row) for row in cursor.fetchall()]
            
            # Limpiar la lista actual
            self.automation_list.clear()
            
            # Filtrar y agregar items que coincidan
            for automation in automations:
                # Buscar en nombre, query_name y platform
                searchable_text = f"{automation['name']} {automation.get('query_name', '')} {automation.get('platform', '')}".lower()
                
                if text in searchable_text:
                    item = QListWidgetItem(automation['name'])
                    # Agregar icono según el estado
                    if automation['enabled']:
                        item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
                    else:
                        item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))
                    
                    # Agregar tooltip con información
                    tooltip = f"""
                    Name: {automation['name']}
                    Query: {automation.get('query_name', 'N/A')}
                    Platform: {automation.get('platform', 'N/A')}
                    Schedule: {automation['schedule']}
                    Last Run: {automation['last_run'] or 'Never'}
                    Next Run: {automation['next_run'] or 'Not scheduled'}
                    """
                    item.setToolTip(tooltip)
                    
                    # Guardar datos completos en el item
                    item.setData(Qt.ItemDataRole.UserRole, automation)
                    
                    self.automation_list.addItem(item)
            
            # Actualizar contador en la barra de estado
            self.statusBar().showMessage(f"Found {self.automation_list.count()} automation(s)")
            
        except Exception as e:
            logging.error(f"Error filtering automations: {e}")
            QMessageBox.critical(self, "Error", f"Failed to filter automations: {str(e)}")

    def load_automation(self, item: QListWidgetItem):
        """
        Carga los detalles de una automatización seleccionada en el formulario
        
        Args:
            item (QListWidgetItem): Item de la lista de automatizaciones seleccionado
        """
        try:
            if not item:
                return
                
            # Obtener datos de la automatización
            automation_data = item.data(Qt.ItemDataRole.UserRole)
            if not automation_data:
                return
                
            # Cargar datos básicos
            self.automation_name.setText(automation_data['name'])
            
            # Configurar programación
            schedule_parts = automation_data['schedule'].split('_')
            if len(schedule_parts) == 2:
                schedule_type, schedule_value = schedule_parts
                
                # Establecer tipo de programación
                index = self.schedule_type.findText(
                    schedule_type.capitalize(),
                    Qt.MatchFlag.MatchFixedString
                )
                if index >= 0:
                    self.schedule_type.setCurrentIndex(index)
                
                # Establecer valor de programación
                try:
                    self.schedule_value.setValue(int(schedule_value))
                except (ValueError, TypeError):
                    self.schedule_value.setValue(1)
            
            # Configurar notificaciones
            self.notify_email.setText(automation_data.get('notification_email', ''))
            
            # Configurar exportación automática
            export_enabled = False
            export_format = 'CSV'
            
            # Cargar acciones configuradas
            self.automation_actions.clear()
            actions = self.get_automation_actions(automation_data['id'])
            for action in actions:
                item = QListWidgetItem(action['type'])
                
                # Configurar icono según el tipo de acción
                if action['type'] == "Export Results":
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                    export_enabled = True
                    export_format = action['config'].get('format', 'CSV').upper()
                elif action['type'] == "Send Email":
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation))
                elif action['type'] == "Execute Script":
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_CommandLink))
                elif action['type'] == "Generate Report":
                    item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
                
                # Agregar tooltip con detalles de la acción
                tooltip = f"""
                Type: {action['type']}
                Enabled: {'Yes' if action['enabled'] else 'No'}
                """
                for key, value in action['config'].items():
                    tooltip += f"\n{key}: {value}"
                item.setToolTip(tooltip)
                
                # Guardar configuración completa en el item
                item.setData(Qt.ItemDataRole.UserRole, action)
                
                self.automation_actions.addItem(item)
            
            # Configurar estado de exportación
            self.export_enabled.setChecked(export_enabled)
            index = self.export_format.findText(export_format, Qt.MatchFlag.MatchFixedString)
            if index >= 0:
                self.export_format.setCurrentIndex(index)
            
            # Actualizar estado de los botones
            self.delete_automation_btn.setEnabled(True)
            self.run_now_btn.setEnabled(True)
            
            # Mostrar información adicional en la barra de estado
            status = f"Loaded automation: {automation_data['name']} | "
            status += f"Last run: {automation_data['last_run'] or 'Never'} | "
            status += f"Next run: {automation_data['next_run'] or 'Not scheduled'}"
            self.statusBar().showMessage(status)

        except Exception as e:
            logging.error(f"Error loading automation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load automation details: {str(e)}")

    def get_automation_actions(self, automation_id: int) -> List[Dict]:
        """
        Obtiene las acciones configuradas para una automatización
        
        Args:
            automation_id (int): ID de la automatización
            
        Returns:
            List[Dict]: Lista de acciones configuradas
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM automation_actions 
                    WHERE automation_id = ?
                    ORDER BY execution_order
                """, (automation_id,))
                
                actions = []
                for row in cursor.fetchall():
                    action_data = dict(row)
                    # Convertir la configuración JSON a diccionario
                    try:
                        action_data['config'] = json.loads(action_data['config'])
                    except (json.JSONDecodeError, TypeError):
                        action_data['config'] = {}
                    actions.append(action_data)
                    
                return actions
                
        except Exception as e:
            logging.error(f"Error getting automation actions: {e}")
            return []

    def save_automation_actions(self, automation_id: int, actions: List[Dict]):
        """
        Guarda las acciones configuradas para una automatización
        
        Args:
            automation_id (int): ID de la automatización
            actions (List[Dict]): Lista de acciones a guardar
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Eliminar acciones existentes
                cursor.execute(
                    "DELETE FROM automation_actions WHERE automation_id = ?",
                    (automation_id,)
                )
                
                # Insertar nuevas acciones
                for i, action in enumerate(actions):
                    cursor.execute("""
                        INSERT INTO automation_actions (
                            automation_id, type, enabled, config, execution_order
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        automation_id,
                        action['type'],
                        action['enabled'],
                        json.dumps(action['config']),
                        i
                    ))
                    
        except Exception as e:
            logging.error(f"Error saving automation actions: {e}")
            raise
    def save_automation(self):
        """Save automation configuration"""
        try:
            name = self.automation_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Warning", "Automation name is required")
                return
                
            # Get current query data
            query_id = None
            current_item = self.automation_list.currentItem()
            if current_item:
                automation_data = current_item.data(Qt.ItemDataRole.UserRole)
                query_id = automation_data.get('query_id')
            
            # Prepare schedule
            schedule_type = self.schedule_type.currentText()
            schedule_value = self.schedule_value.value()
            schedule = f"{schedule_type.lower()}_{schedule_value}"
            
            # Get actions
            actions = []
            for i in range(self.automation_actions.count()):
                item = self.automation_actions.item(i)
                actions.append(item.data(Qt.ItemDataRole.UserRole))
            
            # Save to database
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO saved_searches (
                        name, query_id, schedule, notification_email,
                        enabled, last_run, next_run
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    name,
                    query_id,
                    schedule,
                    self.notify_email.text(),
                    True,
                    None,
                    self.calculate_next_run(schedule)
                ))
                
                # Save actions
                search_id = cursor.lastrowid
                self.save_automation_actions(search_id, actions)
            
            self.load_automations()
            QMessageBox.information(self, "Success", "Automation saved successfully")
            
        except Exception as e:
            logging.error(f"Error saving automation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save automation: {str(e)}")

    def calculate_next_run(self, schedule: str) -> datetime.datetime:
        """Calculate next run time based on schedule"""
        now = datetime.datetime.now()
        schedule_type, value = schedule.split('_')
        value = int(value)
        
        if schedule_type == 'daily':
            return now + datetime.timedelta(days=1)
        elif schedule_type == 'weekly':
            return now + datetime.timedelta(weeks=1)
        elif schedule_type == 'monthly':
            return now + datetime.timedelta(days=30)
        else:  # custom
            return now + datetime.timedelta(hours=value)

    def delete_automation(self):
        """Delete selected automation"""
        try:
            current_item = self.automation_list.currentItem()
            if not current_item:
                return
                
            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                "Are you sure you want to delete this automation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                automation_data = current_item.data(Qt.ItemDataRole.UserRole)
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM saved_searches WHERE id = ?",
                        (automation_data['id'],)
                    )
                
                self.load_automations()
                QMessageBox.information(self, "Success", "Automation deleted successfully")
                
        except Exception as e:
            logging.error(f"Error deleting automation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete automation: {str(e)}")

    def run_automation(self):
        """Run selected automation immediately"""
        try:
            current_item = self.automation_list.currentItem()
            if not current_item:
                return
                
            automation_data = current_item.data(Qt.ItemDataRole.UserRole)
            
            # Execute search
            query_data = self.get_query_by_id(automation_data['query_id'])
            if not query_data:
                raise ValueError("Query not found")
                
            platform = query_data['platform']
            query = query_data['query']
            
            # Create and start search worker
            self.search_worker = SearchWorker(self.api_manager, platform, query)
            self.search_worker.finished.connect(
                lambda results: self.handle_automation_results(results, automation_data)
            )
            self.search_worker.error.connect(self.handle_search_error)
            self.search_worker.start()
            
            self.statusBar().showMessage("Running automation...")
            
        except Exception as e:
            logging.error(f"Error running automation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to run automation: {str(e)}")

    def handle_automation_results(self, results: SearchResult, automation_data: dict):
        """Handle results from automated search"""
        try:
            # Process results
            self.results_analyzer.load_results(results)
            stats = self.results_analyzer.generate_statistics()
            
            # Execute configured actions
            self.execute_automation_actions(automation_data, results, stats)
            
            # Update last run time
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE saved_searches 
                    SET last_run = CURRENT_TIMESTAMP,
                        next_run = ?
                    WHERE id = ?
                """, (
                    self.calculate_next_run(automation_data['schedule']),
                    automation_data['id']
                ))
            
            self.statusBar().showMessage("Automation completed successfully")
            
        except Exception as e:
            logging.error(f"Error handling automation results: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to process automation results: {str(e)}"
            )

    def execute_automation_actions(self, automation_data: dict, results: SearchResult, stats: dict):
        """Execute configured automation actions"""
        try:
            for action in self.get_automation_actions(automation_data['id']):
                if not action['enabled']:
                    continue
                    
                if action['type'] == "Export Results":
                    self.export_automation_results(results, action['config'])
                elif action['type'] == "Send Email":
                    self.send_automation_email(results, stats, action['config'])
                elif action['type'] == "Execute Script":
                    self.execute_automation_script(results, action['config'])
                elif action['type'] == "Generate Report":
                    self.generate_automation_report(results, stats, action['config'])
                    
        except Exception as e:
            logging.error(f"Error executing automation actions: {e}")
            raise

    def perform_analysis(self):
        """Perform analysis based on current settings"""
        try:
            analysis_type = self.analysis_type.currentText()
            time_range = self.time_range.currentText()
            data_source = self.data_source.currentText()
            
            # Get data for analysis
            if data_source == "Current Results":
                if not self.results_analyzer.df is not None:
                    QMessageBox.warning(self, "Warning", "No current results available")
                    return
                df = self.results_analyzer.df
            else:
                df = self.load_analysis_data(time_range)
                
            if df.empty:
                QMessageBox.warning(self, "Warning", "No data available for analysis")
                return
                
            # Perform analysis
            if analysis_type == "Geographic Distribution":
                results = self.analyze_geographic_distribution(df)
            elif analysis_type == "Service Analysis":
                results = self.analyze_services(df)
            elif analysis_type == "Port Distribution":
                results = self.analyze_ports(df)
            elif analysis_type == "Vulnerability Statistics":
                results = self.analyze_vulnerabilities(df)
            elif analysis_type == "Certificate Analysis":
                results = self.analyze_certificates(df)
            else:  # Custom Analysis
                results = self.perform_custom_analysis(df)
                
            # Display results
            self.display_analysis_results(results)
            
            # Update visualization
            self.update_visualization()
            
        except Exception as e:
            logging.error(f"Error performing analysis: {e}")
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")

    def analyze_geographic_distribution(self, df: pd.DataFrame) -> Dict:
        """Analyze geographic distribution of results"""
        try:
            # Get country column based on platform
            if 'country_name' in df.columns:
                country_col = 'country_name'
            elif 'location' in df.columns:
                country_col = df['location'].apply(lambda x: x.get('country'))
            else:
                raise ValueError("No geographic data available")
                
            # Calculate distribution
            distribution = df[country_col].value_counts()
            
            # Calculate percentages
            total = len(df)
            percentages = (distribution / total * 100).round(2)
            
            # Prepare results
            results = {
                'distribution': distribution.to_dict(),
                'percentages': percentages.to_dict(),
                'total_countries': len(distribution),
                'top_countries': distribution.head(10).to_dict(),
                'metadata': {
                    'analysis_type': 'geographic',
                    'total_results': total,
                    'timestamp': datetime.datetime.now()
                }
            }
            
            return results
            
        except Exception as e:
            logging.error(f"Error analyzing geographic distribution: {e}")
            raise

    def analyze_services(self, df: pd.DataFrame) -> Dict:
        """Analyze services in results"""
        try:
            results = {
                'service_counts': {},
                'version_distribution': {},
                'port_mapping': {},
                'metadata': {
                    'analysis_type': 'services',
                    'total_results': len(df),
                    'timestamp': datetime.datetime.now()
                }
            }
            
            # Analysis logic varies by platform
            if 'product' in df.columns:  # Shodan
                results['service_counts'] = df['product'].value_counts().to_dict()
                if 'version' in df.columns:
                    results['version_distribution'] = df.groupby('product')['version'].value_counts().to_dict()
                if 'port' in df.columns:
                    results['port_mapping'] = df.groupby('product')['port'].value_counts().to_dict()
            elif 'services' in df.columns:  # Censys
                services = df['services'].explode()
                results['service_counts'] = services.value_counts().to_dict()
                
            return results
            
        except Exception as e:
            logging.error(f"Error analyzing services: {e}")
            raise

    def update_visualization(self):
        """Update the visualization based on current analysis"""
        try:
            viz_type = self.viz_type.currentText()
            
            if not hasattr(self.results_analyzer, 'df') or self.results_analyzer.df is None:
                return
                
            df = self.results_analyzer.df
            
            # Create visualization based on type
            if viz_type == "Bar Chart":
                self.create_bar_chart(df)
            elif viz_type == "Line Chart":
                self.create_line_chart(df)
            elif viz_type == "Pie Chart":
                self.create_pie_chart(df)
            elif viz_type == "Heat Map":
                self.create_heat_map(df)
            elif viz_type == "Geographic Map":
                self.create_geographic_map(df)
            else:  # Custom Chart
                self.create_custom_chart(df)
                
        except Exception as e:
            logging.error(f"Error updating visualization: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update visualization: {str(e)}")

    def save_visualization(self):
        """Save current visualization"""
        try:
            # Get file path
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Visualization",
                "",
                "PNG Files (*.png);;SVG Files (*.svg);;HTML Files (*.html)"
            )
            
            if not file_path:
                return
                
            # Export based on file type
            if file_path.endswith('.html'):
                self.export_interactive_visualization(file_path)
            else:
                self.export_static_visualization(file_path)
                
            QMessageBox.information(
                self,
                "Success",
                "Visualization saved successfully"
            )
            
        except Exception as e:
            logging.error(f"Error saving visualization: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save visualization: {str(e)}")
    def create_analysis_tab(self) -> QWidget:
        """Create the analysis and visualization tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create toolbar
        toolbar_layout = QHBoxLayout()
        
        # Analysis type selector
        self.analysis_type = QComboBox()
        self.analysis_type.addItems([
            "Geographic Distribution",
            "Service Analysis",
            "Port Distribution",
            "Vulnerability Statistics",
            "Certificate Analysis",
            "Custom Analysis"
        ])
        toolbar_layout.addWidget(QLabel("Analysis Type:"))
        toolbar_layout.addWidget(self.analysis_type)
        
        # Time range selector
        self.time_range = QComboBox()
        self.time_range.addItems([
            "Last 24 Hours",
            "Last Week",
            "Last Month",
            "Custom Range"
        ])
        toolbar_layout.addWidget(QLabel("Time Range:"))
        toolbar_layout.addWidget(self.time_range)
        
        # Data source selector
        self.data_source = QComboBox()
        self.data_source.addItems([
            "Current Results",
            "Saved Results",
            "All Results"
        ])
        toolbar_layout.addWidget(QLabel("Data Source:"))
        toolbar_layout.addWidget(self.data_source)
        
        # Analysis button
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.perform_analysis)
        toolbar_layout.addWidget(self.analyze_btn)
        
        layout.addLayout(toolbar_layout)
        
        # Main content area with splitter
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Results panel
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        # Results table
        self.results_table = QTableWidget()
        results_layout.addWidget(self.results_table)
        
        # Export button
        self.export_results_btn = QPushButton("Export Results")
        self.export_results_btn.clicked.connect(self.export_analysis)
        results_layout.addWidget(self.export_results_btn)
        
        results_group.setLayout(results_layout)
        content_splitter.addWidget(results_group)
        
        # Visualization panel
        viz_group = QGroupBox("Visualization")
        viz_layout = QVBoxLayout()
        
        # Visualization type selector
        self.viz_type = QComboBox()
        self.viz_type.addItems([
            "Bar Chart",
            "Line Chart",
            "Pie Chart",
            "Heat Map",
            "Geographic Map",
            "Custom Chart"
        ])
        viz_layout.addWidget(self.viz_type)
        
        # Visualization area (placeholder)
        self.viz_area = QWidget()
        viz_layout.addWidget(self.viz_area)
        
        # Visualization controls
        viz_controls = QHBoxLayout()
        self.update_viz_btn = QPushButton("Update")
        self.update_viz_btn.clicked.connect(self.update_visualization)
        self.save_viz_btn = QPushButton("Save")
        self.save_viz_btn.clicked.connect(self.save_visualization)
        
        viz_controls.addWidget(self.update_viz_btn)
        viz_controls.addWidget(self.save_viz_btn)
        viz_layout.addLayout(viz_controls)
        
        viz_group.setLayout(viz_layout)
        content_splitter.addWidget(viz_group)
        
        layout.addWidget(content_splitter)
        
        return tab
    def setup_menu(self):
        """Setup the application menu"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        new_action = QAction('New Search', self)
        new_action.setShortcut('Ctrl+N')
        new_action.triggered.connect(self.clear_search_form)
        file_menu.addAction(new_action)
        
        save_action = QAction('Save Query', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_current_query)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def load_settings(self):
        """Load application settings"""
        settings = QSettings('SearchKit', 'Professional Search Toolkit')
        
        # Restore window geometry
        geometry = settings.value('geometry')
        if geometry:
            self.restoreGeometry(geometry)
            
        # Restore window state
        state = settings.value('windowState')
        if state:
            self.restoreState(state)

    def closeEvent(self, event):
        """Handle application close event"""
        try:
            # Cerrar sesión asincrónicamente
            if hasattr(self, 'api_manager'):
                self.api_manager.loop.run_until_complete(self.api_manager.close_session())
                self.api_manager.loop.close()
            
            # Guardar configuración
            settings = QSettings('SearchKit', 'Professional Search Toolkit')
            settings.setValue('geometry', self.saveGeometry())
            settings.setValue('windowState', self.saveState())
            
            super().closeEvent(event)
        except Exception as e:
            logging.error(f"Error during application shutdown: {e}")

    def get_category_fields(self, category: str) -> List[str]:
        """Get fields for a category"""
        if category == "Network":
            return ["Port", "Protocol", "IP Range", "Domain"]
        elif category == "Services":
            return ["Product", "Version", "Service Name"]
        elif category == "Vulnerabilities":
            return ["CVE", "CVSS Score", "Vulnerability Type"]
        elif category == "Certificates":
            return ["Issuer", "Subject", "Validity"]
        else:  # Custom
            return ["Custom Query"]

    def update_query_preview(self):
        """Update the query preview based on current inputs"""
        try:
            params = {}
            for category, section in self.query_sections.items():
                for field_layout in section.findChildren(QHBoxLayout):
                    label = field_layout.itemAt(0).widget()
                    input_field = field_layout.itemAt(1).widget()
                    if input_field.text():
                        params[label.text().lower()] = input_field.text()
            
            platform = 'shodan' if self.shodan_radio.isChecked() else 'censys'
            query = self.query_builder.build_query(platform, params)
            self.query_preview.setText(query)
            
        except Exception as e:
            self.query_preview.setText(f"Error building query: {str(e)}")

    def execute_search(self):
        """Execute the search query with proper error handling"""
        query = self.query_preview.toPlainText()
        if not query:
            QMessageBox.warning(self, "Warning", "Please enter a search query")
            return
        
        platform = 'shodan' if self.shodan_radio.isChecked() else 'censys'
        
        # Verificar que tengamos las claves API necesarias
        if platform == 'shodan' and not self.config.get('api_keys', {}).get('shodan'):
            QMessageBox.warning(
                self,
                "API Key Missing",
                "Please configure your Shodan API key in the configuration file."
            )
            return
        elif platform == 'censys' and (
            not self.config.get('api_keys', {}).get('censys_id') or
            not self.config.get('api_keys', {}).get('censys_secret')
        ):
            QMessageBox.warning(
                self,
                "API Key Missing",
                "Please configure your Censys API credentials in the configuration file."
            )
            return
        
        try:
            # Create and start search worker
            self.search_worker = SearchWorker(self.api_manager, platform, query)
            self.search_worker.finished.connect(self.handle_search_results)
            self.search_worker.error.connect(self.handle_search_error)
            self.search_worker.progress.connect(self.update_progress)
            self.search_worker.start()
            
            # Update UI
            self.search_button.setEnabled(False)
            self.statusBar().showMessage("Searching...")
            
        except Exception as e:
            logging.error(f"Search execution error: {e}")
            QMessageBox.critical(
                self,
                "Search Error",
                f"Failed to execute search: {str(e)}"
            )
            self.search_button.setEnabled(True)
            self.statusBar().showMessage("Search failed")   
    def export_analysis(self):
        """Export analysis results in various formats"""
        try:
            # Verificar que haya resultados para exportar
            if not hasattr(self.results_analyzer, 'df') or self.results_analyzer.df is None:
                QMessageBox.warning(self, "Warning", "No analysis results available to export")
                return

            # Obtener el tipo de análisis actual
            analysis_type = self.analysis_type.currentText()
            
            # Mostrar diálogo de exportación
            export_dialog = QDialog(self)
            export_dialog.setWindowTitle("Export Analysis Results")
            export_dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout(export_dialog)
            
            # Selector de formato
            format_layout = QHBoxLayout()
            format_layout.addWidget(QLabel("Export Format:"))
            format_selector = QComboBox()
            format_selector.addItems(["CSV", "Excel", "JSON", "HTML", "PDF", "Markdown"])
            format_layout.addWidget(format_selector)
            layout.addLayout(format_layout)
            
            # Opciones de exportación
            options_group = QGroupBox("Export Options")
            options_layout = QVBoxLayout()
            
            # Checkbox para incluir visualizaciones
            include_viz = QCheckBox("Include Visualizations")
            include_viz.setChecked(True)
            options_layout.addWidget(include_viz)
            
            # Checkbox para incluir metadata
            include_meta = QCheckBox("Include Metadata")
            include_meta.setChecked(True)
            options_layout.addWidget(include_meta)
            
            # Checkbox para compresión
            compress_export = QCheckBox("Compress Export")
            compress_export.setChecked(False)
            options_layout.addWidget(compress_export)
            
            options_group.setLayout(options_layout)
            layout.addWidget(options_group)
            
            # Botones
            button_layout = QHBoxLayout()
            export_button = QPushButton("Export")
            cancel_button = QPushButton("Cancel")
            button_layout.addWidget(export_button)
            button_layout.addWidget(cancel_button)
            layout.addLayout(button_layout)
            
            # Conectar eventos
            export_button.clicked.connect(export_dialog.accept)
            cancel_button.clicked.connect(export_dialog.reject)
            
            # Mostrar diálogo
            if export_dialog.exec() != QDialog.DialogCode.Accepted:
                return
            
            # Obtener configuración de exportación
            export_format = format_selector.currentText().lower()
            include_visualizations = include_viz.isChecked()
            include_metadata = include_meta.isChecked()
            compress = compress_export.isChecked()
            
            # Obtener ruta de guardado
            file_filters = {
                'csv': 'CSV Files (*.csv)',
                'excel': 'Excel Files (*.xlsx)',
                'json': 'JSON Files (*.json)',
                'html': 'HTML Files (*.html)',
                'pdf': 'PDF Files (*.pdf)',
                'markdown': 'Markdown Files (*.md)'
            }
            
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Analysis Export",
                os.path.join(EXPORT_DIR, f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"),
                file_filters[export_format]
            )
            
            if not file_path:
                return
                
            # Preparar datos para exportación
            export_data = self.prepare_export_data(
                analysis_type,
                include_visualizations,
                include_metadata
            )
            
            # Exportar según el formato
            if export_format == 'csv':
                self.export_to_csv(file_path, export_data)
            elif export_format == 'excel':
                self.export_to_excel(file_path, export_data)
            elif export_format == 'json':
                self.export_to_json(file_path, export_data)
            elif export_format == 'html':
                self.export_to_html(file_path, export_data)
            elif export_format == 'pdf':
                self.export_to_pdf(file_path, export_data)
            elif export_format == 'markdown':
                self.export_to_markdown(file_path, export_data)
                
            # Comprimir si es necesario
            if compress:
                self.compress_export(file_path)
                
            QMessageBox.information(
                self,
                "Success",
                f"Analysis results exported successfully to {file_path}"
            )
            
            # Registrar la exportación
            self.log_export(file_path, export_format, export_data['metadata'])
            
        except Exception as e:
            logging.error(f"Error exporting analysis: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export analysis: {str(e)}")

    def prepare_export_data(self, analysis_type: str, include_viz: bool, include_meta: bool) -> Dict:
        """Prepare data for export"""
        export_data = {
            'analysis_type': analysis_type,
            'timestamp': datetime.datetime.now(),
            'data': {}
        }
        
        # Agregar datos del análisis
        df = self.results_analyzer.df
        if analysis_type == "Geographic Distribution":
            export_data['data'] = self.prepare_geographic_data(df)
        elif analysis_type == "Service Analysis":
            export_data['data'] = self.prepare_service_data(df)
        elif analysis_type == "Port Distribution":
            export_data['data'] = self.prepare_port_data(df)
        elif analysis_type == "Vulnerability Statistics":
            export_data['data'] = self.prepare_vulnerability_data(df)
        elif analysis_type == "Certificate Analysis":
            export_data['data'] = self.prepare_certificate_data(df)
        
        # Agregar visualizaciones si se solicitan
        if include_viz:
            export_data['visualizations'] = self.capture_visualizations()
        
        # Agregar metadata si se solicita
        if include_meta:
            export_data['metadata'] = {
                'total_records': len(df),
                'analysis_parameters': self.get_analysis_parameters(),
                'data_source': self.data_source.currentText(),
                'time_range': self.time_range.currentText(),
                'export_timestamp': datetime.datetime.now(),
                'platform': self.results_analyzer.platform,
                'query': self.results_analyzer.query
            }
        
        return export_data

    def export_to_csv(self, file_path: str, export_data: Dict):
        """Export data to CSV format"""
        try:
            # Convertir datos a DataFrame
            df = pd.DataFrame(export_data['data'])
            
            # Exportar datos principales
            df.to_csv(file_path, index=False)
            
            # Si hay metadata, exportar en archivo separado
            if 'metadata' in export_data:
                meta_path = file_path.replace('.csv', '_metadata.csv')
                pd.DataFrame([export_data['metadata']]).to_csv(meta_path, index=False)
            
        except Exception as e:
            logging.error(f"Error exporting to CSV: {e}")
            raise

    def export_to_excel(self, file_path: str, export_data: Dict):
        """Export data to Excel format"""
        try:
            with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
                # Exportar datos principales
                pd.DataFrame(export_data['data']).to_excel(
                    writer,
                    sheet_name='Analysis Results',
                    index=False
                )
                
                # Exportar metadata si existe
                if 'metadata' in export_data:
                    pd.DataFrame([export_data['metadata']]).to_excel(
                        writer,
                        sheet_name='Metadata',
                        index=False
                    )
                
                # Agregar visualizaciones si existen
                if 'visualizations' in export_data:
                    ws = writer.book.create_sheet('Visualizations')
                    for i, viz in enumerate(export_data['visualizations']):
                        img = openpyxl.drawing.image.Image(viz)
                        ws.add_image(img, f'A{i * 20 + 1}')
                        
        except Exception as e:
            logging.error(f"Error exporting to Excel: {e}")
            raise

    def export_to_json(self, file_path: str, export_data: Dict):
        """Export data to JSON format"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
                
        except Exception as e:
            logging.error(f"Error exporting to JSON: {e}")
            raise

    def export_to_html(self, file_path: str, export_data: Dict):
            """Export data to HTML format"""
            try:
                # Crear template HTML
                template = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Analysis Export - {analysis_type}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        .section {{ margin-bottom: 30px; }}
                        table {{ border-collapse: collapse; width: 100%; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #f2f2f2; }}
                        .viz-container {{ margin: 20px 0; }}
                    </style>
                </head>
                <body>
                    <h1>Analysis Results - {analysis_type}</h1>
                    
                    <!-- Metadata Section -->
                    {metadata_section}
                    
                    <!-- Results Section -->
                    {results_section}
                    
                    <!-- Visualizations Section -->
                    {visualizations_section}
                </body>
                </html>
                """
                
                # Generar secciones
                metadata_html = self.generate_metadata_html(export_data) if 'metadata' in export_data else ""
                results_html = self.generate_results_html(export_data['data'])
                viz_html = self.generate_visualizations_html(export_data) if 'visualizations' in export_data else ""
                
                # Compilar HTML final
                html_content = template.format(
                    analysis_type=export_data['analysis_type'],
                    metadata_section=metadata_html,
                    results_section=results_html,
                    visualizations_section=viz_html
                )
                
                # Guardar archivo
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            except Exception as e:
                logging.error(f"Error exporting to HTML: {e}")
                raise

    def compress_export(self, file_path: str):
        """Compress exported file"""
        try:
            import zipfile
            
            zip_path = file_path + '.zip'
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(file_path, os.path.basename(file_path))
                
            # Eliminar archivo original
            os.remove(file_path)
            
        except Exception as e:
            logging.error(f"Error compressing export: {e}")
            raise

    def log_export(self, file_path: str, format: str, metadata: Dict):
        """Log export operation"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO export_logs (
                        file_path, format, metadata_json, export_timestamp
                    ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    file_path,
                    format,
                    json.dumps(metadata)
                ))
                
        except Exception as e:
            logging.error(f"Error logging export: {e}")
            # No levantar excepción para no interrumpir la exportación
    def handle_search_results(self, results: SearchResult):
        """Handle search results"""
        try:
            # Store results
            query_id = self.db_manager.add_query(
                name=f"Search {datetime.datetime.now()}",
                platform=results.platform,
                query=results.query
            )
            self.db_manager.add_result(query_id, results)
            
            # Analyze results
            self.results_analyzer.load_results(results)
            stats = self.results_analyzer.generate_statistics()
            
            # Update UI
            self.display_results(results, stats)
            self.update_recent_searches()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error processing results: {str(e)}")
        finally:
            self.search_button.setEnabled(True)
            self.statusBar().showMessage("Ready")
    def update_recent_searches(self):
        """Update the recent searches list"""
        self.load_recent_searches()

    def handle_search_error(self, error_message: str):
        """Handle search errors"""
        QMessageBox.critical(self, "Search Error", error_message)
        self.search_button.setEnabled(True)
        self.statusBar().showMessage("Ready")

    def update_progress(self, value: int):
        """Update progress bar"""
        self.statusBar().showMessage(f"Searching... {value}%")
    def save_template(self):
        """Save the current template to the database"""
        try:
            # Validar campos requeridos
            name = self.template_name.text().strip()
            content = self.template_content.toPlainText().strip()
            
            if not name or not content:
                QMessageBox.warning(
                    self,
                    "Validation Error",
                    "Template name and content are required."
                )
                return
            
            # Preparar datos del template
            template_data = {
                'name': name,
                'platform': self.template_platform.currentText(),
                'category': self.template_category.currentText(),
                'content': content,
                'parameters': self.template_params.toPlainText().strip(),
                'description': self.template_description.toPlainText().strip()
            }
            
            # Validar el contenido del template
            if not self.validate_template_content(template_data):
                return
            
            # Guardar el template
            template_id = self.db_manager.save_template(template_data)
            
            # Actualizar la lista de templates
            self.load_category_templates(self.template_categories.currentItem())
            
            # Mostrar mensaje de éxito
            QMessageBox.information(
                self,
                "Success",
                f"Template '{name}' saved successfully."
            )
            
        except Exception as e:
            logging.error(f"Error saving template: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save template: {str(e)}"
            )

    def validate_template_content(self, template_data: Dict) -> bool:
        """
        Validate the template content and parameters
        
        Args:
            template_data (Dict): Template data to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Validar sintaxis del template
            content = template_data['content']
            if not self.query_builder.validate_query(
                template_data['platform'],
                content
            ):
                raise ValueError("Invalid query syntax")
            
            # Validar parámetros YAML
            if template_data['parameters']:
                try:
                    yaml.safe_load(template_data['parameters'])
                except yaml.YAMLError as e:
                    raise ValueError(f"Invalid parameters YAML: {str(e)}")
            
            return True
            
        except Exception as e:
            QMessageBox.warning(
                self,
                "Validation Error",
                f"Template validation failed: {str(e)}"
            )
            return False

    def delete_template(self):
        """Delete the selected template"""
        try:
            current_item = self.templates_list.currentItem()
            if not current_item:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Please select a template to delete."
                )
                return
            
            template_id = current_item.data(Qt.ItemDataRole.UserRole)
            template_name = current_item.text()
            
            # Confirmar eliminación
            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Are you sure you want to delete template '{template_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Eliminar template
                if self.db_manager.delete_template(template_id):
                    # Actualizar lista
                    self.load_category_templates(self.template_categories.currentItem())
                    # Limpiar formulario
                    self.clear_template_form()
                    QMessageBox.information(
                        self,
                        "Success",
                        f"Template '{template_name}' deleted successfully."
                    )
                else:
                    raise Exception("Template not found")
                    
        except Exception as e:
            logging.error(f"Error deleting template: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to delete template: {str(e)}"
            )

    def test_template(self):
        """Test the current template with sample parameters"""
        try:
            content = self.template_content.toPlainText().strip()
            params = self.template_params.toPlainText().strip()
            
            if not content:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Template content is required for testing."
                )
                return
            
            # Si hay parámetros, validarlos
            if params:
                try:
                    params_dict = yaml.safe_load(params)
                except yaml.YAMLError as e:
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Invalid parameters YAML: {str(e)}"
                    )
                    return
            else:
                params_dict = {}
            
            # Intentar generar query desde el template
            platform = self.template_platform.currentText().lower()
            result_query = self.query_builder.build_from_template(
                content,
                params_dict,
                platform
            )
            
            # Mostrar resultado
            dialog = QDialog(self)
            dialog.setWindowTitle("Template Test Result")
            dialog.setMinimumWidth(600)
            
            layout = QVBoxLayout(dialog)
            
            # Agregar texto explicativo
            layout.addWidget(QLabel("Generated Query:"))
            
            # Mostrar query generado
            result_text = QTextEdit()
            result_text.setPlainText(result_query)
            result_text.setReadOnly(True)
            layout.addWidget(result_text)
            
            # Botón para cerrar
            close_button = QPushButton("Close")
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button)
            
            dialog.exec()
            
        except Exception as e:
            logging.error(f"Error testing template: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Template test failed: {str(e)}"
            )

    def clear_template_form(self):
        """Clear all template form inputs"""
        self.template_name.clear()
        self.template_content.clear()
        self.template_params.clear()
        self.template_description.clear()
        self.template_platform.setCurrentIndex(0)
        self.template_category.setCurrentIndex(0)
    def load_category_templates(self, category_item: QListWidgetItem):
        """
        Carga los templates de la categoría seleccionada
        
        Args:
            category_item (QListWidgetItem): Item de categoría seleccionado
        """
        try:
            if not category_item:
                return
                
            # Obtener el nombre de la categoría
            category_name = category_item.text()
            
            # Limpiar la lista actual de templates
            self.templates_list.clear()
            
            # Obtener templates de la base de datos
            templates = self.db_manager.get_templates_by_category(category_name)
            
            # Agregar templates a la lista
            for template in templates:
                item = QListWidgetItem(template['name'])
                # Guardar los datos completos del template en el item
                item.setData(Qt.ItemDataRole.UserRole, template)
                
                # Si el template tiene descripción, usarla como tooltip
                if template.get('description'):
                    item.setToolTip(template['description'])
                    
                self.templates_list.addItem(item)
                
            # Actualizar el estado de los botones
            self.update_template_buttons()
            
            # Mostrar mensaje en la barra de estado
            self.statusBar().showMessage(
                f"Loaded {len(templates)} templates for category: {category_name}"
            )
            
        except Exception as e:
            logging.error(f"Error loading category templates: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load templates: {str(e)}"
            )
            self.statusBar().showMessage("Error loading templates")

    def create_template_tables(self):
        """
        Crea las tablas necesarias para el manejo de templates si no existen
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla principal de templates
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS templates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        platform TEXT NOT NULL,
                        query_template TEXT NOT NULL,
                        parameters TEXT,
                        description TEXT,
                        author TEXT,
                        version TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabla de uso de templates
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS template_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        template_id INTEGER,
                        query_id INTEGER,
                        parameters_used TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user TEXT,
                        FOREIGN KEY (template_id) REFERENCES templates (id),
                        FOREIGN KEY (query_id) REFERENCES queries (id)
                    )
                """)
                
                # Tabla de validaciones
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS template_validations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        template_id INTEGER,
                        is_valid BOOLEAN,
                        error_message TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (template_id) REFERENCES templates (id)
                    )
                """)
                
                # Tabla de modificaciones
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS template_modifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        template_id INTEGER,
                        field_modified TEXT,
                        old_value TEXT,
                        new_value TEXT,
                        modified_by TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (template_id) REFERENCES templates (id)
                    )
                """)
                
                # Tabla de tags
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS template_tags (
                        template_id INTEGER,
                        tag TEXT,
                        PRIMARY KEY (template_id, tag),
                        FOREIGN KEY (template_id) REFERENCES templates (id)
                    )
                """)
                
                # Índices
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_templates_category 
                    ON templates(category)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_template_usage_template_id 
                    ON template_usage(template_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_template_validations_template_id 
                    ON template_validations(template_id)
                """)
                
        except Exception as e:
            logging.error(f"Error creating template tables: {e}")
            raise DatabaseError(f"Failed to create template tables: {str(e)}")
    def load_template_details(self, template_item: QListWidgetItem):
        """
        Carga los detalles del template seleccionado en el formulario
        
        Args:
            template_item (QListWidgetItem): Item de template seleccionado
        """
        try:
            if not template_item:
                return
                
            # Obtener datos del template
            template_data = template_item.data(Qt.ItemDataRole.UserRole)
            if not template_data:
                return
                
            # Actualizar campos del formulario
            self.template_name.setText(template_data['name'])
            
            # Establecer la plataforma
            platform_index = self.template_platform.findText(
                template_data['platform'],
                Qt.MatchFlag.MatchFixedString
            )
            if platform_index >= 0:
                self.template_platform.setCurrentIndex(platform_index)
                
            # Establecer la categoría
            category_index = self.template_category.findText(
                template_data['category'],
                Qt.MatchFlag.MatchFixedString
            )
            if category_index >= 0:
                self.template_category.setCurrentIndex(category_index)
                
            # Establecer el contenido
            self.template_content.setPlainText(template_data['query_template'])
            
            # Establecer parámetros si existen
            if template_data.get('parameters'):
                self.template_params.setPlainText(template_data['parameters'])
            else:
                self.template_params.clear()
                
            # Establecer descripción si existe
            if template_data.get('description'):
                self.template_description.setPlainText(template_data['description'])
            else:
                self.template_description.clear()
                
            # Actualizar información adicional en la barra de estado
            status_message = (
                f"Template: {template_data['name']} | "
                f"Created: {template_data.get('created_at', 'N/A')} | "
                f"Usage Count: {template_data.get('usage_count', 0)}"
            )
            self.statusBar().showMessage(status_message)
            
            # Actualizar el estado de los botones
            self.update_template_buttons()
            
        except Exception as e:
            logging.error(f"Error loading template details: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load template details: {str(e)}"
            )
            self.statusBar().showMessage("Error loading template details")

    def update_template_buttons(self):
        """Actualiza el estado de los botones de acción de templates"""
        try:
            # Verificar si hay un template seleccionado
            has_template_selected = bool(self.templates_list.currentItem())
            
            # Habilitar/deshabilitar botones según si hay selección
            self.delete_template_btn.setEnabled(has_template_selected)
            self.test_template_btn.setEnabled(has_template_selected)
            
            # El botón de guardar siempre está habilitado para permitir nuevos templates
            self.save_template_btn.setEnabled(True)
            
        except Exception as e:
            logging.error(f"Error updating template buttons: {e}")

    def validate_template_fields(self) -> bool:
        """
        Valida los campos del formulario de template
        
        Returns:
            bool: True si los campos son válidos, False en caso contrario
        """
        try:
            # Verificar nombre
            if not self.template_name.text().strip():
                QMessageBox.warning(
                    self,
                    "Validation Error",
                    "Template name is required"
                )
                self.template_name.setFocus()
                return False
                
            # Verificar contenido
            if not self.template_content.toPlainText().strip():
                QMessageBox.warning(
                    self,
                    "Validation Error",
                    "Template content is required"
                )
                self.template_content.setFocus()
                return False
                
            # Verificar sintaxis de parámetros si existen
            params_text = self.template_params.toPlainText().strip()
            if params_text:
                try:
                    yaml.safe_load(params_text)
                except yaml.YAMLError as e:
                    QMessageBox.warning(
                        self,
                        "Validation Error",
                        f"Invalid parameters YAML syntax: {str(e)}"
                    )
                    self.template_params.setFocus()
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Error validating template fields: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Validation error: {str(e)}"
            )
            return False

    def create_new_template(self):
        """Limpia el formulario para crear un nuevo template"""
        try:
            # Confirmar si hay cambios sin guardar
            if self.has_unsaved_changes():
                reply = QMessageBox.question(
                    self,
                    "Unsaved Changes",
                    "You have unsaved changes. Do you want to continue and discard them?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
            
            # Limpiar formulario
            self.clear_template_form()
            
            # Deseleccionar template actual
            self.templates_list.clearSelection()
            
            # Actualizar botones
            self.update_template_buttons()
            
            # Enfocar el campo de nombre
            self.template_name.setFocus()
            
        except Exception as e:
            logging.error(f"Error creating new template: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to create new template: {str(e)}"
            )

    def has_unsaved_changes(self) -> bool:
        """
        Verifica si hay cambios sin guardar en el formulario
        
        Returns:
            bool: True si hay cambios sin guardar, False en caso contrario
        """
        try:
            current_item = self.templates_list.currentItem()
            if not current_item:
                # Si no hay template seleccionado, verificar si hay datos en el formulario
                return bool(
                    self.template_name.text().strip() or
                    self.template_content.toPlainText().strip() or
                    self.template_params.toPlainText().strip() or
                    self.template_description.toPlainText().strip()
                )
                
            # Obtener datos del template actual
            template_data = current_item.data(Qt.ItemDataRole.UserRole)
            
            # Comparar con datos del formulario
            return (
                template_data['name'] != self.template_name.text().strip() or
                template_data['platform'] != self.template_platform.currentText() or
                template_data['category'] != self.template_category.currentText() or
                template_data['query_template'] != self.template_content.toPlainText().strip() or
                template_data.get('parameters', '') != self.template_params.toPlainText().strip() or
                template_data.get('description', '') != self.template_description.toPlainText().strip()
            )
            
        except Exception as e:
            logging.error(f"Error checking for unsaved changes: {e}")
            return False

def main():
    """Main application entry point"""
    # Create necessary directories
    for directory in ['logs', 'data', 'config', 'exports', 'styles']:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # Setup logging
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Start application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Load and apply stylesheet
        try:
            with open('styles/dark.qss', 'r') as f:
                app.setStyleSheet(f.read())
        except FileNotFoundError:
            logging.warning("Style file not found. Using default style.")
        
        # Create and show main window
        window = MainWindow()
        window.show()
        
        # Start the event loop
        sys.exit(app.exec())
        
    except Exception as e:
        logging.critical(f"Application failed to start: {str(e)}")
        raise

if __name__ == '__main__':
    main()