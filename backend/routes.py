import os
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from .models import db, Scan, Report
from .utils import validate_file, save_upload, compute_hashes, cleanup_file
from . import static_engine, ml_engine

bp = Blueprint('main', __name__)


# ── Static file serving ───────────────────────────────────────────────────────

@bp.route('/')
def index():
    """Serve the single-page frontend."""
    return send_from_directory('../static', 'index.html')


@bp.route('/<path:filename>')
def static_files(filename):
    """Serve any static asset (CSS, JS, images)."""
    return send_from_directory('../static', filename)


# ── API ───────────────────────────────────────────────────────────────────────

@bp.route('/api/scan', methods=['POST'])
def upload_and_scan():
    """
    POST /api/scan
    Body: multipart/form-data  { file: <binary> }
    Synchronous — returns full scan + report JSON when done.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file field in request'}), 400

    f = request.files['file']
    if not f or not f.filename:
        return jsonify({'error': 'Empty file upload'}), 400

    # ── Validate ─────────────────────────────────────────────────────────
    is_valid, error_msg = validate_file(f)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # ── Save with UUID name ───────────────────────────────────────────────
    upload_folder = current_app.config['UPLOAD_FOLDER']
    try:
        stored_name, full_path = save_upload(f, upload_folder)
    except Exception:
        return jsonify({'error': 'Failed to save uploaded file'}), 500

    file_size = os.path.getsize(full_path)
    md5, sha256 = compute_hashes(full_path)

    # ── Persist scan record ───────────────────────────────────────────────
    scan = Scan(
        original_filename=f.filename,
        stored_filename=stored_name,
        file_size=file_size,
        md5=md5,
        sha256=sha256,
        status='running',
    )
    db.session.add(scan)
    db.session.commit()

    # ── Analyse ───────────────────────────────────────────────────────────
    try:
        static_result = static_engine.analyze(
            full_path,
            yara_rules_path=current_app.config['YARA_RULES_PATH'],
            die_binary=current_app.config['DIE_BINARY'],
        )
        ml_result = ml_engine.predict(full_path)
        verdict_data = ml_engine.aggregate_verdict(ml_result, static_result)

        report = Report(
            scan_id=scan.id,
            verdict=verdict_data['verdict'],
            confidence=verdict_data['confidence'],
            ml_score=verdict_data['ml_score'],
            is_packed=verdict_data['is_packed'],
            packer_name=verdict_data['packer_name'],
            yara_matches=verdict_data['yara_matches'],
            indicators=verdict_data['indicators'],
            pe_info={
                'headers': static_result.get('pe_headers', {}),
                'sections': static_result.get('sections', []),
                'imports': static_result.get('imports', {}),
            },
            static_features={
                'strings': static_result.get('strings', {}),
                'packing': static_result.get('packing', {}),
                'die_output': static_result.get('die_output', {}),
            },
        )
        db.session.add(report)
        scan.status = 'done'
        db.session.commit()

        return jsonify({
            'scan': scan.to_dict(),
            'report': report.to_dict(),
        }), 200

    except Exception as e:
        scan.status = 'failed'
        db.session.commit()
        cleanup_file(full_path)
        current_app.logger.exception('Scan pipeline error')
        return jsonify({'error': 'Scan pipeline failed. Check server logs.'}), 500


@bp.route('/api/report/<scan_id>', methods=['GET'])
def get_report(scan_id):
    """GET /api/report/<scan_id> — retrieve a completed report by scan ID."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    if not scan.report:
        return jsonify({'error': 'Report not available yet'}), 404
    return jsonify({
        'scan': scan.to_dict(),
        'report': scan.report.to_dict(),
    })


@bp.route('/api/history', methods=['GET'])
def history():
    """GET /api/history?page=1&limit=20 — paginated scan history."""
    page = request.args.get('page', 1, type=int)
    limit = min(request.args.get('limit', 20, type=int), 100)

    pagination = (
        Scan.query
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=limit, error_out=False)
    )

    items = []
    for s in pagination.items:
        entry = s.to_dict()
        entry['verdict'] = s.report.verdict if s.report else None
        entry['confidence'] = s.report.confidence if s.report else None
        items.append(entry)

    return jsonify({
        'scans': items,
        'total': pagination.total,
        'page': page,
        'pages': pagination.pages,
    })


@bp.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """DELETE /api/scan/<scan_id> — remove scan, report, and uploaded file."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], scan.stored_filename)
    cleanup_file(file_path)

    db.session.delete(scan)
    db.session.commit()

    return jsonify({'deleted': scan_id})


@bp.route('/api/status', methods=['GET'])
def status():
    """GET /api/status — health check + capability flags."""
    return jsonify({
        'status': 'ok',
        'model_loaded': ml_engine.is_model_loaded(),
        'ember_available': ml_engine.EMBER_AVAILABLE,
        'yara_available': static_engine.YARA_AVAILABLE,
        'pefile_available': static_engine.PEFILE_AVAILABLE,
    })
