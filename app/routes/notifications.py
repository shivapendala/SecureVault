from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app import db
from app.models.notification import Notification
from app.utils.decorators import login_required

notifications_bp = Blueprint('notifications', __name__)

@notifications_bp.route('/', strict_slashes=False)
@notifications_bp.route('', strict_slashes=False)
@login_required
def index():
    user_id = session.get('user_id')
    tab_filter = request.args.get('tab', 'all').lower()

    base_query = Notification.query.filter(
        (Notification.user_id == user_id) | (Notification.user_id == None)
    )

    if tab_filter == 'unread':
        notifications = base_query.filter_by(is_read=False).order_by(Notification.created_at.desc()).all()
    elif tab_filter == 'read':
        notifications = base_query.filter_by(is_read=True).order_by(Notification.created_at.desc()).all()
    else:
        notifications = base_query.order_by(Notification.created_at.desc()).all()

    total_count = base_query.count()
    unread_count = base_query.filter_by(is_read=False).count()
    read_count = base_query.filter_by(is_read=True).count()

    return render_template(
        'notifications/index.html',
        notifications=notifications,
        tab_filter=tab_filter,
        total_count=total_count,
        unread_count=unread_count,
        read_count=read_count
    )

@notifications_bp.route('/<int:notif_id>/mark-read', methods=['POST'])
@login_required
def mark_read(notif_id):
    user_id = session.get('user_id')
    notif = Notification.query.filter(
        Notification.id == notif_id,
        (Notification.user_id == user_id) | (Notification.user_id == None)
    ).first_or_404()

    notif.mark_as_read()
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify({'status': 'success', 'notif_id': notif_id, 'is_read': True})

    flash("Notification marked as read.", "success")
    return redirect(request.referrer or url_for('notifications.index'))

@notifications_bp.route('/<int:notif_id>/mark-unread', methods=['POST'])
@login_required
def mark_unread(notif_id):
    user_id = session.get('user_id')
    notif = Notification.query.filter(
        Notification.id == notif_id,
        (Notification.user_id == user_id) | (Notification.user_id == None)
    ).first_or_404()

    notif.is_read = False
    notif.read_at = None
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify({'status': 'success', 'notif_id': notif_id, 'is_read': False})

    flash("Notification marked as unread.", "info")
    return redirect(request.referrer or url_for('notifications.index'))

@notifications_bp.route('/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    user_id = session.get('user_id')
    unread_notifs = Notification.query.filter(
        (Notification.user_id == user_id) | (Notification.user_id == None),
        Notification.is_read == False
    ).all()

    for n in unread_notifs:
        n.mark_as_read()
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify({'status': 'success', 'updated_count': len(unread_notifs)})

    flash(f"All {len(unread_notifs)} unread notifications marked as read.", "success")
    return redirect(request.referrer or url_for('notifications.index'))

@notifications_bp.route('/<int:notif_id>/delete', methods=['POST'])
@login_required
def delete_notification(notif_id):
    user_id = session.get('user_id')
    notif = Notification.query.filter(
        Notification.id == notif_id,
        (Notification.user_id == user_id) | (Notification.user_id == None)
    ).first_or_404()

    db.session.delete(notif)
    db.session.commit()

    flash("Notification removed.", "info")
    return redirect(request.referrer or url_for('notifications.index'))

@notifications_bp.route('/api/unread-count')
@login_required
def api_unread_count():
    user_id = session.get('user_id')
    unread_count = Notification.query.filter(
        (Notification.user_id == user_id) | (Notification.user_id == None),
        Notification.is_read == False
    ).count()
    return jsonify({'status': 'success', 'unread_count': unread_count})
