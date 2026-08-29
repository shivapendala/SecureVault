import os
import io
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file, current_app
from werkzeug.utils import secure_filename
from app import db
from app.models.file import FileVault
from app.models.security_log import SecurityLog
from app.models.notification import Notification
from app.utils.decorators import login_required, log_audit
from app.utils.file_security import (
    validate_file_upload,
    calculate_bytes_hashes,
    encrypt_file_data,
    decrypt_file_data,
    MAX_FILE_SIZE_BYTES
)

file_sec_bp = Blueprint('file_security', __name__)

def get_upload_directory() -> str:
    """Ensure upload directory exists and return absolute path."""
    upload_dir = os.path.join(current_app.root_path, '..', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

@file_sec_bp.route('/')
@login_required
def index():
    user_id = session.get('user_id')
    files = FileVault.query.order_by(FileVault.uploaded_at.desc()).all()
    
    total_files = len(files)
    total_bytes = sum(f.file_size or 0 for f in files)
    verified_files = sum(1 for f in files if f.integrity_status == 'VERIFIED')
    flagged_files = sum(1 for f in files if f.integrity_status == 'MODIFIED_WARNING')

    return render_template(
        'file_security/index.html',
        files=files,
        total_files=total_files,
        total_bytes=total_bytes,
        verified_files=verified_files,
        flagged_files=flagged_files
    )

@file_sec_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    user_id = session.get('user_id')
    user_name = session.get('user_name', 'Operator')
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'

    if 'file' not in request.files:
        flash("No file part provided in upload payload.", "warning")
        return redirect(url_for('file_security.index'))

    file_obj = request.files['file']
    is_valid, err_msg = validate_file_upload(file_obj)
    if not is_valid:
        flash(err_msg, "danger")
        db.session.add(SecurityLog(
            user_id=user_id,
            event_type='FILE_UPLOAD_REJECTED',
            severity='HIGH',
            details=f"File upload rejected for '{file_obj.filename}': {err_msg}",
            ip_address=ip_addr,
            status='BLOCKED'
        ))
        db.session.commit()
        return redirect(url_for('file_security.index'))

    # Read raw content
    raw_bytes = file_obj.read()
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        flash("File exceeds maximum allowed size (25 MB).", "danger")
        return redirect(url_for('file_security.index'))

    # Calculate cryptographic hashes
    sha256_checksum, md5_checksum = calculate_bytes_hashes(raw_bytes)
    
    # Secure storage filename
    orig_name = secure_filename(file_obj.filename)
    unique_name = f"{uuid.uuid4().hex}_{orig_name}"
    upload_dir = get_upload_directory()
    disk_path = os.path.join(upload_dir, unique_name)

    # Encrypt bytes with Fernet AES-256
    encrypt_flag = request.form.get('encrypt', 'true') in ['true', True, '1', 1, 'on']
    if encrypt_flag:
        stored_bytes = encrypt_file_data(raw_bytes)
        enc_algo = 'AES-256-Fernet'
    else:
        stored_bytes = raw_bytes
        enc_algo = 'None (Plaintext)'

    # Save to disk
    with open(disk_path, 'wb') as f:
        f.write(stored_bytes)

    # Save metadata to database
    description = request.form.get('description', '').strip()
    mime_type = file_obj.content_type or 'application/octet-stream'

    file_record = FileVault(
        user_id=user_id,
        filename=unique_name,
        original_filename=orig_name,
        file_path=os.path.relpath(disk_path, current_app.root_path),
        mime_type=mime_type,
        file_size=len(raw_bytes),
        checksum_sha256=sha256_checksum,
        checksum_md5=md5_checksum,
        is_encrypted=encrypt_flag,
        encryption_algorithm=enc_algo,
        description=description,
        integrity_status='VERIFIED',
        last_verified_at=datetime.utcnow()
    )

    db.session.add(file_record)
    
    # Security log
    db.session.add(SecurityLog(
        user_id=user_id,
        event_type='FILE_UPLOAD_SUCCESS',
        severity='INFO',
        details=f"File '{orig_name}' ({file_record.format_size()}) uploaded with SHA-256 {sha256_checksum[:12]}...",
        ip_address=ip_addr,
        status='SUCCESS'
    ))

    # Notification
    db.session.add(Notification(
        user_id=user_id,
        title='File Vault: New Asset Stored',
        message=f"File '{orig_name}' secured with SHA-256 fingerprint {sha256_checksum[:16]}...",
        category='system',
        priority='normal'
    ))

    db.session.commit()
    log_audit('FILE_UPLOAD', 'FileVault', file_record.id, f"Uploaded '{orig_name}' (SHA256: {sha256_checksum})", status='SUCCESS')
    flash(f"File '{orig_name}' uploaded and cryptographic SHA-256 baseline computed successfully!", "success")
    return redirect(url_for('file_security.index'))

@file_sec_bp.route('/<int:file_id>/verify', methods=['POST'])
@login_required
def verify_stored_file(file_id):
    file_record = FileVault.query.get_or_404(file_id)
    upload_dir = get_upload_directory()
    disk_path = os.path.join(upload_dir, file_record.filename)
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'

    if not os.path.exists(disk_path):
        file_record.integrity_status = 'MODIFIED_WARNING'
        file_record.last_verified_at = datetime.utcnow()
        db.session.commit()
        flash(f"Security Alert: File '{file_record.original_filename}' is missing from physical storage!", "danger")
        return redirect(url_for('file_security.index'))

    # Read and decrypt (if encrypted) to compute current SHA-256
    with open(disk_path, 'rb') as f:
        stored_data = f.read()

    try:
        if file_record.is_encrypted:
            actual_data = decrypt_file_data(stored_data)
        else:
            actual_data = stored_data

        current_sha256, _ = calculate_bytes_hashes(actual_data)
        is_matched = file_record.verify_checksum(current_sha256)

        file_record.last_verified_at = datetime.utcnow()
        if is_matched:
            file_record.integrity_status = 'VERIFIED'
            flash(f"Integrity Verified: '{file_record.original_filename}' matches baseline SHA-256 fingerprint ({current_sha256[:16]}...).", "success")
            db.session.add(SecurityLog(
                user_id=session.get('user_id'),
                event_type='FILE_INTEGRITY_VERIFIED',
                severity='INFO',
                details=f"SHA-256 integrity check passed for '{file_record.original_filename}'.",
                ip_address=ip_addr,
                status='SUCCESS'
            ))
        else:
            file_record.integrity_status = 'MODIFIED_WARNING'
            flash(f"CRITICAL WARNING: Integrity violation detected for '{file_record.original_filename}'! Expected SHA-256 {file_record.checksum_sha256[:12]}... but computed {current_sha256[:12]}...", "danger")
            db.session.add(SecurityLog(
                user_id=session.get('user_id'),
                event_type='FILE_INTEGRITY_VIOLATION',
                severity='CRITICAL',
                details=f"Integrity violation detected for '{file_record.original_filename}' (SHA-256 mismatch).",
                ip_address=ip_addr,
                status='FAILURE'
            ))

        db.session.commit()
    except Exception as e:
        flash(f"Decryption/Verification error: {str(e)}", "danger")

    return redirect(url_for('file_security.index'))

@file_sec_bp.route('/<int:file_id>/download')
@login_required
def download_file(file_id):
    file_record = FileVault.query.get_or_404(file_id)
    upload_dir = get_upload_directory()
    disk_path = os.path.join(upload_dir, file_record.filename)

    if not os.path.exists(disk_path):
        flash("Target file not found in storage.", "danger")
        return redirect(url_for('file_security.index'))

    with open(disk_path, 'rb') as f:
        stored_bytes = f.read()

    if file_record.is_encrypted:
        try:
            download_bytes = decrypt_file_data(stored_bytes)
        except Exception as e:
            flash(f"Decryption error on download: {str(e)}", "danger")
            return redirect(url_for('file_security.index'))
    else:
        download_bytes = stored_bytes

    log_audit('FILE_DOWNLOAD', 'FileVault', file_record.id, f"Downloaded '{file_record.original_filename}'", status='SUCCESS')
    return send_file(
        io.BytesIO(download_bytes),
        mimetype=file_record.mime_type or 'application/octet-stream',
        as_attachment=True,
        download_name=file_record.original_filename
    )

@file_sec_bp.route('/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = FileVault.query.get_or_404(file_id)
    upload_dir = get_upload_directory()
    disk_path = os.path.join(upload_dir, file_record.filename)

    if os.path.exists(disk_path):
        try:
            os.remove(disk_path)
        except Exception:
            pass

    orig_name = file_record.original_filename
    db.session.delete(file_record)
    db.session.commit()

    log_audit('FILE_DELETE', 'FileVault', file_id, f"Deleted file '{orig_name}' from vault", status='SUCCESS')
    flash(f"File '{orig_name}' and stored cryptographic metadata securely deleted.", "info")
    return redirect(url_for('file_security.index'))

@file_sec_bp.route('/api/verify-hash', methods=['POST'])
@login_required
def api_verify_hash():
    """Verify an uploaded file or hash against stored vault files or calculate hash."""
    if 'file' in request.files:
        file_obj = request.files['file']
        raw_bytes = file_obj.read()
        sha256_hash, md5_hash = calculate_bytes_hashes(raw_bytes)
        size = len(raw_bytes)
        filename = file_obj.filename
    else:
        data = request.get_json() or {}
        sha256_hash = data.get('sha256', '').strip()
        md5_hash = ""
        size = 0
        filename = ""

    # Check if this SHA-256 exists in our database
    matching_record = FileVault.query.filter_by(checksum_sha256=sha256_hash).first() if sha256_hash else None

    return jsonify({
        'status': 'success',
        'calculated_sha256': sha256_hash,
        'calculated_md5': md5_hash,
        'file_size': size,
        'matched': matching_record is not None,
        'matched_file': {
            'id': matching_record.id,
            'original_filename': matching_record.original_filename,
            'uploaded_at': matching_record.uploaded_at.strftime('%Y-%m-%d %H:%M:%S'),
            'file_size': matching_record.format_size()
        } if matching_record else None
    })
