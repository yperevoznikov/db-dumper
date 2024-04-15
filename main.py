import json
import logging
import subprocess
import sys
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _run_cmd(description, cmd):
    logger.info("CMD: %s", cmd)
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except Exception as e:
        logger.error("Error during %s: %s", description, e)
        sys.exit(1)
    logger.info('Output: %s', output)


def main(settings):
    logger.info("-" * 10 + "Starting script" + "-" * 10)
    os.chdir(settings.get("project_path"))
    logger.info("Working in directory: %s", os.getcwd())

    cmd_docker_compose = settings.get("cmd_docker_compose")
    db_table = settings.get("db_table")
    db_user = settings.get("db_user")
    db_password = settings.get("db_password")
    db_name = settings.get("db_name")
    dump_filename = settings.get("dump_filename")
    dump_container_path = settings.get("dump_container_dir") + dump_filename
    dump_host_path = settings.get("dump_host_dir") + dump_filename
    dump_host_home_path = settings.get("dump_host_home_path")

    # Create db dump inside container
    logger.info("Start dumping, table: %s", db_table)
    container_cmd = f'mysqldump --verbose -u {db_user} -p{db_password} {db_name} {db_table} > {dump_container_path}'
    host_cmd = f'{cmd_docker_compose} exec db bash -c "{container_cmd}"'
    _run_cmd("db dumping", host_cmd)

    # Make file fully accessible to access from host machine
    logger.info("Make file fully accessible to access from host machine: %s", dump_container_path)
    container_cmd = f'chmod --changes --verbose 777 {dump_container_path}'
    host_cmd = f'{cmd_docker_compose} exec db bash -c "{container_cmd}"'
    _run_cmd("permission change", host_cmd)

    # Remove previous archive
    logger.info("Remove original file in container")
    try:
        os.unlink(f'{dump_host_home_path}{dump_filename}')
    except FileNotFoundError:
        logger.debug("no previous sql file found")
    try:
        os.unlink(f'{dump_host_home_path}{dump_filename}.gz')
    except FileNotFoundError:
        logger.debug("no previous sql archive file found")

    # Copy to home directory
    logger.info("Copy to home directory")
    host_cmd = f'cp -rf {dump_host_path} {dump_host_home_path}{dump_filename}'
    _run_cmd("dump copy", host_cmd)

    # Remove original file
    logger.info("Remove original file in container")
    container_cmd = f'rm {dump_container_path}'
    host_cmd = f'{cmd_docker_compose} exec db bash -c "{container_cmd}"'
    _run_cmd("removing file in container", host_cmd)

    # Archive dump
    logger.info("Remove original file in container")
    host_cmd = f'gzip {dump_host_home_path}{dump_filename}'
    _run_cmd("archive dump", host_cmd)

    # Upload to S3
    s3 = boto3.client(
        's3',
        region_name=settings.get('aws_region'),
        aws_access_key_id=settings.get('aws_access_key_id'),
        aws_secret_access_key=settings.get('aws_secret_access_key')
    )
    try:
        s3.upload_file(
            f'{dump_host_home_path}{dump_filename}.gz',
            settings.get("aws_s3_db_dumps_bucket"),
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + '.sql.gz'
        )
    except ClientError as e:
        logging.error(e)
        sys.exit(1)

    # Remove previous archive
    logger.info("Remove archieve")
    os.unlink(f'{dump_host_home_path}{dump_filename}.gz')

    # Remove old dumps from AWS S3
    logger.info("Remove old dumps from AWS S3")
    get_last_modified = lambda obj: int(obj['LastModified'].strftime('%s'))
    try:
        s3_file_records = s3.list_objects_v2(Bucket=settings.get("aws_s3_db_dumps_bucket")).get('Contents', [])
        s3_file_record_keys = [obj['Key'] for obj in sorted(s3_file_records, key=get_last_modified)]
        s3_keys_to_delete = s3_file_record_keys[:-settings.get("dumps_files_keep")]
        for s3_file_record_key in s3_keys_to_delete:
            logger.info("Removing old dump: %s", s3_file_record_key)
            s3.delete_object(Bucket=settings.get("aws_s3_db_dumps_bucket"), Key=s3_file_record_key)
    except ClientError as e:
        logging.error(e)
        sys.exit(1)


if __name__ == '__main__':
    with open("settings.json", "r") as f:
        settings = json.load(f)

    logging.basicConfig(
        handlers=[
            TimedRotatingFileHandler(
                settings.get("log_file_pathname"),
                when='W0', # rotate every week
                backupCount=settings.get("log_files_keep")
            ),
            logging.StreamHandler(sys.stdout)
        ],
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    main(settings)
