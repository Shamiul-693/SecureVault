"""Application startup and UI smoke tests (headless, QT_QPA_PLATFORM=offscreen)."""
import os
import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from tests.conftest import FAST_KDF, MASTER  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def controller(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREVAULT_DATA_DIR", str(tmp_path))
    from app.application import AppController
    c = AppController(qapp, db_file=tmp_path / "vault.db", kdf_params=FAST_KDF)
    assert c.start()
    yield c
    if c.main_window:
        c.main_window.close()
    if c.login_window:
        c.login_window.close()
    c.shutdown()


def _unlock_via_ui(controller, password=MASTER):
    login = controller.login_window
    login.password.setText(password)
    login.submit()
    QApplication.processEvents()


def test_first_run_shows_setup(controller):
    assert controller.login_window is not None
    assert controller.login_window.setup_mode
    assert controller.main_window is None


def test_setup_unlock_lock_cycle(controller, monkeypatch):
    import ui.login_window as lw
    monkeypatch.setattr(lw, "confirm", lambda *a, **k: True)
    login = controller.login_window
    login.password.setText("weak")
    login.confirm.setText("weak")
    login.submit()
    assert controller.main_window is None and login.error.isVisible()

    login.password.setText(MASTER)
    login.confirm.setText(MASTER)
    login.submit()
    assert controller.main_window is not None and controller.vault.is_unlocked
    key_ref = controller.vault._key

    controller.lock()
    assert not controller.vault.is_unlocked
    assert key_ref == bytearray(32)  # key buffer wiped
    assert controller.main_window is None
    assert not controller.login_window.setup_mode

    _unlock_via_ui(controller, "Wrong-Password-000!")
    assert controller.main_window is None and controller.login_window.error.isVisible()
    _unlock_via_ui(controller)
    assert controller.main_window is not None


def test_all_pages_and_dialogs(controller):
    from ui.account_dialog import AccountDialog
    from ui.category_dialog import CategoryDialog
    from ui.dialogs import ChangePasswordDialog
    key = controller.auth.setup(MASTER)
    controller.on_unlocked(key)
    mw = controller.main_window

    dlg = AccountDialog(controller.ctx, None)
    dlg.title.setText("GitHub")
    dlg.username.setText("dev")
    dlg.url.setText("github.com")
    dlg.generate()
    dlg.save()
    assert dlg.saved_entry is not None and dlg.saved_entry.url == "https://github.com"

    bad = AccountDialog(controller.ctx, None)
    bad.save()
    assert not bad.error.isHidden() and bad.saved_entry is None

    for page in ("dashboard", "generator", "security", "settings", "view:all", "view:type:card", "view:trash"):
        mw.navigate(page)
        assert mw.current_page() == page

    mw.open_entry(dlg.saved_entry.id)
    assert mw.vault_page.detail.entry.id == dlg.saved_entry.id
    mw.vault_page.search.setText("zzz-no-match")
    assert mw.vault_page.table.rowCount() == 0
    mw.vault_page.search.setText("git")
    assert mw.vault_page.table.rowCount() == 1

    gen = mw.generator_page
    gen.spin.setValue(32)
    assert len(gen.output.text()) == 32
    for box in gen.sets[1:]:
        box.setChecked(False)
    gen.sets[0].setChecked(False)  # last one cannot be unchecked
    assert gen.sets[0].isChecked()

    cat = CategoryDialog(controller.ctx)
    assert cat.list.count() >= 10
    ChangePasswordDialog(controller.ctx)

    controller.ctx.set_theme("light")
    assert controller.main_window is not mw
    assert controller.ctx.theme == "light"


def test_clipboard_clears(controller, qapp):
    clip = controller.clipboard
    clip.timeout_seconds = 1
    clip.copy("secret-value", "Password")
    assert QGuiApplication.clipboard().text() == "secret-value"
    deadline = time.time() + 3
    while clip.pending and time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.05)
    assert QGuiApplication.clipboard().text() == ""

    clip.copy("secret-value", "Password")
    QGuiApplication.clipboard().setText("user copied something else")
    clip.clear_if_ours()
    assert QGuiApplication.clipboard().text() == "user copied something else"


def test_auto_lock_after_inactivity(controller):
    key = controller.auth.setup(MASTER)
    controller.on_unlocked(key)
    controller.ctx.set_setting("auto_lock_minutes", 1)
    controller.last_activity = time.monotonic() - 61
    controller._check_idle()
    assert not controller.vault.is_unlocked and controller.main_window is None


def test_lock_clears_copied_password(controller):
    key = controller.auth.setup(MASTER)
    controller.on_unlocked(key)
    controller.ctx.copy_secret("pw-in-clipboard", "Password", None)
    controller.lock()
    assert QGuiApplication.clipboard().text() == ""


def test_restore_from_settings_locks_vault(controller, monkeypatch):
    key = controller.auth.setup(MASTER)
    controller.on_unlocked(key)
    controller.vault.add_entry("Before", "u", "p")
    path = controller.backups.create_backup(controller.vault.key)
    controller.vault.add_entry("After", "u", "p")
    controller.backups.restore_backup(path, MASTER, controller.vault.key)
    controller.lock("restored")
    _unlock_via_ui(controller)
    assert [e.title for e in controller.vault.list_entries()] == ["Before"]


def test_open_url_rejects_non_http(controller, monkeypatch):
    from app import application
    opened = []
    monkeypatch.setattr(application.QDesktopServices, "openUrl", lambda u: opened.append(u.toString()))
    controller.ctx.open_url("file:///C:/Windows/System32/calc.exe")
    controller.ctx.open_url("https://github.com")
    assert opened == ["https://github.com"]


def test_corrupt_database_detected(qapp, tmp_path, monkeypatch):
    from app import application
    path = tmp_path / "vault.db"
    path.write_bytes(b"garbage" * 1000)
    monkeypatch.setattr(application.AppController, "_handle_corrupt_database", lambda self, reason: False)
    c = application.AppController(qapp, db_file=path, kdf_params=FAST_KDF)
    assert c.start() is False


def test_item_types_folders_trash_ui(controller, monkeypatch):
    import ui.vault_page as vp
    from ui.account_dialog import ItemDialog
    monkeypatch.setattr(vp, "confirm", lambda *a, **k: True)
    key = controller.auth.setup(MASTER)
    controller.on_unlocked(key)
    mw = controller.main_window
    ctx = controller.ctx
    page = mw.vault_page

    # add one of each type through the dialog
    d = ItemDialog(ctx, None, "card")
    d.card_fields["number"].setText("4242 4242 4242 4242")
    d.card_fields["expiry"].setText("12/30")
    d.card_fields["cvv"].setText("123")
    d.save()
    assert d.saved_entry.title == "Visa •••• 4242" and d.saved_entry.extra["cvv"] == "123"
    n = ItemDialog(ctx, None, "note")
    n.title.setText("Router")
    n.save()
    assert n.saved_entry is None  # empty note rejected
    n.notes.setPlainText("admin / secret")
    n.save()
    i = ItemDialog(ctx, None, "identity")
    i.set_type("identity")
    i.title.setText("Me")
    i.identity_fields["full_name"].setText("Shamiul Islam")
    i.save()
    login = ctx.vault.add_entry("GitHub", "dev", "pw-123-Strong!x")

    mw.refresh_sidebar()
    assert mw.nav_items["view:all"].count_label.text() == "4"
    assert mw.nav_items["view:type:card"].count_label.text() == "1"

    # folders
    fid = ctx.db.add_folder("Family")
    mw.refresh_sidebar()
    assert f"view:folder:{fid}" in mw.nav_items
    mw.navigate("view:all")
    page.move_to_folder([login.id, d.saved_entry.id], fid)
    mw.navigate(f"view:folder:{fid}")
    assert page.table.rowCount() == 2 and page.title.text() == "Family"

    # multi-select -> bulk bar, then trash
    mw.navigate("view:all")
    assert page.table.rowCount() == 4
    page.table.selectAll()
    assert page.bulk.isVisibleTo(page) and len(page.selected_ids()) == 4
    page.trash_items(page.selected_ids()[:2])
    assert page.table.rowCount() == 2
    mw.navigate("view:trash")
    assert page.table.rowCount() == 2 and page.empty_trash_btn.isVisibleTo(page)
    page.restore_items([page.table.item(0, 0).data(vp.Qt.UserRole)])
    assert page.table.rowCount() == 1
    page.empty_trash()
    assert page.table.rowCount() == 0 and ctx.db.entry_count() == 3

    # detail panel renders every type
    for e in ctx.vault.list_entries():
        page.detail.show_entry(e)
        assert page.detail.title.text() == e.title

    # recommendations: no backup yet -> backup card; running it creates a backup
    mw.navigate("view:all")
    assert page.recs_host.isVisibleTo(page)
    backup = next(r for r in [c.rec for c in page.recs_host.findChildren(vp.RecommendationCard)] if r.action == "backup")
    page.run_recommendation(backup)
    assert ctx.db.get_setting("last_backup_at")
    weak = ctx.vault.add_entry("Weak", "u", "password")
    page.refresh()
    rec = next(c.rec for c in page.recs_host.findChildren(vp.RecommendationCard) if c.rec.key.startswith("weak"))
    page.dismiss_recommendation(rec)
    assert rec.key in ctx.db.get_setting("dismissed_recommendations")
    assert weak.id

    # theme rebuild keeps the current view
    mw.navigate("view:type:card")
    ctx.set_theme("light")
    assert controller.main_window.current_page() == "view:type:card"
