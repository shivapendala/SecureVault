/**
 * SecureVault Secret Decryption & Generator Logic
 */

let activeRevealTimer = null;

function revealSecretModal(secretId, secretTitle) {
    const modalEl = document.getElementById('secretRevealModal');
    if (!modalEl) return;

    const titleEl = document.getElementById('revealModalTitle');
    const valueEl = document.getElementById('revealedSecretValue');
    const copyBtn = document.getElementById('revealCopyBtn');
    const timerBadge = document.getElementById('revealTimerBadge');

    titleEl.textContent = `Decrypting: ${secretTitle}`;
    valueEl.value = 'Decrypting AES payload...';
    timerBadge.textContent = 'Auto-masking in 15s';

    const bsModal = new bootstrap.Modal(modalEl);
    bsModal.show();

    fetch(`/vault/${secretId}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            valueEl.value = data.secret;
            copyBtn.onclick = () => window.copyToClipboard(data.secret, copyBtn);

            // Start 15s auto-mask timer
            let secondsLeft = 15;
            if (activeRevealTimer) clearInterval(activeRevealTimer);

            activeRevealTimer = setInterval(() => {
                secondsLeft--;
                if (secondsLeft > 0) {
                    timerBadge.textContent = `Auto-masking in ${secondsLeft}s`;
                } else {
                    clearInterval(activeRevealTimer);
                    valueEl.value = '•••••••••••••••• (Secret Masked for Security)';
                    timerBadge.textContent = 'Secret Masked';
                }
            }, 1000);
        } else {
            valueEl.value = 'Error: Access Denied';
        }
    })
    .catch(err => {
        valueEl.value = 'Decryption Failed: ' + err;
    });

    modalEl.addEventListener('hidden.bs.modal', () => {
        if (activeRevealTimer) clearInterval(activeRevealTimer);
        valueEl.value = '';
    }, { once: true });
}

function generatePasswordModal() {
    const lengthInput = document.getElementById('pwdLength') || { value: 20 };
    fetch(`/vault/api/generate-password?length=${lengthInput.value}`)
        .then(res => res.json())
        .then(data => {
            const output = document.getElementById('generatedPasswordOutput');
            const entropyBadge = document.getElementById('entropyBadge');
            const targetField = document.getElementById('secret_value');

            if (output) output.value = data.password;
            if (entropyBadge) {
                entropyBadge.textContent = `${data.entropy_analysis.entropy} bits (${data.entropy_analysis.strength})`;
            }
            if (targetField && !targetField.value) {
                targetField.value = data.password;
            }
        });
}

function applyGeneratedPassword() {
    const output = document.getElementById('generatedPasswordOutput');
    const targetField = document.getElementById('secret_value');
    if (output && targetField) {
        targetField.value = output.value;
        const modalEl = document.getElementById('pwdGenModal');
        if (modalEl) {
            const bsModal = bootstrap.Modal.getInstance(modalEl);
            if (bsModal) bsModal.hide();
        }
    }
}
