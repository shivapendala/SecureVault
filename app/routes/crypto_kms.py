from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
from app import db
from app.utils.decorators import login_required, roles_required, admin_required
from app.models.crypto_kms import AsymmetricKeyPair, KeyRotationLog, SecretShareRecord
from app.services.crypto_kms.asymmetric_kms import AsymmetricKmsService
from app.services.crypto_kms.shamir_secret_sharing import ShamirSecretSharingService
from app.services.crypto_kms.digital_signature import DigitalSignatureService
from app.services.crypto_kms.key_rotator import KeyRotatorService

kms_bp = Blueprint('crypto_kms', __name__, url_prefix='/kms')

@kms_bp.route('/')
@login_required
def index():
    # Seed default key if none exists
    if AsymmetricKeyPair.query.count() == 0:
        AsymmetricKmsService.generate_key_pair('SOC-Root-Master-Key', algorithm='RSA-2048')

    keys = AsymmetricKeyPair.query.order_by(AsymmetricKeyPair.created_at.desc()).all()
    rotation_logs = KeyRotationLog.query.order_by(KeyRotationLog.rotated_at.desc()).limit(5).all()
    shares = SecretShareRecord.query.order_by(SecretShareRecord.created_at.desc()).limit(5).all()

    return render_template(
        'crypto_kms/index.html',
        keys=keys,
        rotation_logs=rotation_logs,
        shares=shares
    )

@kms_bp.route('/keys/generate', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Security Analyst', 'Analyst')
def generate_key():
    if request.method == 'POST':
        alias = request.form.get('key_alias', '').strip()
        algo = request.form.get('algorithm', 'RSA-2048').strip()
        period = int(request.form.get('rotation_period_days', 90))

        if not alias:
            flash("Key alias is required.", "warning")
            return redirect(url_for('crypto_kms.generate_key'))

        key = AsymmetricKmsService.generate_key_pair(alias, algorithm=algo, rotation_period_days=period)
        flash(f"Asymmetric key '{alias}' ({algo}) generated with fingerprint {key.key_fingerprint[:16]}...", "success")
        return redirect(url_for('crypto_kms.index'))

    return render_template('crypto_kms/generate_key.html')

@kms_bp.route('/keys/rotate/<int:key_id>', methods=['POST'])
@login_required
@admin_required
def rotate_key(key_id):
    res = KeyRotatorService.rotate_asymmetric_key(key_id, rotated_by_name=session.get('user_name', 'Admin'))
    flash(res['message'], "success")
    return redirect(url_for('crypto_kms.index'))

@kms_bp.route('/shamir', methods=['GET', 'POST'])
@login_required
def shamir_workshop():
    split_result = None
    reconstructed_secret = None

    if request.method == 'POST':
        action_type = request.form.get('action_type', 'split')
        if action_type == 'split':
            secret_val = request.form.get('secret_payload', '').strip()
            label = request.form.get('secret_label', 'Master Enclave Passphrase').strip()
            k = int(request.form.get('threshold_k', 3))
            n = int(request.form.get('total_shares_n', 5))
            if secret_val:
                split_result = ShamirSecretSharingService.split_secret(secret_val, k=k, n=n, label=label)
                flash(f"Secret successfully split into {n} shares (Threshold: {k}).", "success")
        elif action_type == 'combine':
            shares_raw = request.form.get('shares_input', '').strip()
            if shares_raw:
                share_lines = [s.strip() for s in shares_raw.splitlines() if s.strip()]
                try:
                    reconstructed_secret = ShamirSecretSharingService.reconstruct_secret(share_lines)
                    flash("Secret successfully reconstructed using Lagrange polynomial interpolation!", "success")
                except Exception as e:
                    flash(f"Reconstruction failed: {str(e)}", "danger")

    return render_template('crypto_kms/shamir_workshop.html', split_result=split_result, reconstructed_secret=reconstructed_secret)

@kms_bp.route('/sign', methods=['GET', 'POST'])
@login_required
def digital_signer():
    keys = AsymmetricKeyPair.query.filter_by(state='ACTIVE').all()
    sign_result = None
    verify_result = None

    if request.method == 'POST':
        action_type = request.form.get('action_type', 'sign')
        if action_type == 'sign':
            key_id = int(request.form.get('key_id'))
            msg = request.form.get('message_to_sign', '').strip()
            if msg:
                sign_result = DigitalSignatureService.sign_payload(key_id, msg)
                flash("Payload digitally signed with private key.", "success")
        elif action_type == 'verify':
            pub_pem = request.form.get('public_key_pem', '').strip()
            msg = request.form.get('message_to_verify', '').strip()
            sig_b64 = request.form.get('signature_b64', '').strip()
            is_valid = DigitalSignatureService.verify_signature(pub_pem, msg, sig_b64)
            verify_result = {'is_valid': is_valid}
            if is_valid:
                flash("Cryptographic signature is VALID! Attestation authentic.", "success")
            else:
                flash("Signature verification FAILED. Payload modified or wrong key.", "danger")

    return render_template('crypto_kms/digital_signer.html', keys=keys, sign_result=sign_result, verify_result=verify_result)

# REST API Endpoints
@kms_bp.route('/api/generate-key', methods=['POST'])
def api_generate_key():
    data = request.get_json() or {}
    alias = data.get('key_alias', 'API-Generated-Key')
    algo = data.get('algorithm', 'RSA-2048')
    key = AsymmetricKmsService.generate_key_pair(alias, algorithm=algo)
    return jsonify({'success': True, 'key': key.to_dict()}), 201

@kms_bp.route('/api/shamir-split', methods=['POST'])
def api_shamir_split():
    data = request.get_json() or {}
    secret = data.get('secret', '')
    if not secret:
        return jsonify({'success': False, 'error': 'Missing secret parameter'}), 400
    k = int(data.get('k', 3))
    n = int(data.get('n', 5))
    res = ShamirSecretSharingService.split_secret(secret, k=k, n=n)
    return jsonify({'success': True, 'split': res})

@kms_bp.route('/api/shamir-combine', methods=['POST'])
def api_shamir_combine():
    data = request.get_json() or {}
    shares = data.get('shares', [])
    if len(shares) < 2:
        return jsonify({'success': False, 'error': 'At least 2 shares required'}), 400
    rec = ShamirSecretSharingService.reconstruct_secret(shares)
    return jsonify({'success': True, 'reconstructed_secret': rec})
