# -*- coding: utf-8 -*-
"""密标模块日志器。

单独收口，避免与 utils.logger 的预置日志器（db/dashboard 等）互相干扰，
也不额外生成日志文件，仅输出到控制台。
"""
import logging

LOGGER_NAME = 'risk_mark'
LOG_FORMAT = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def _build_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


logger = _build_logger()

__all__ = ['logger', 'LOGGER_NAME']
