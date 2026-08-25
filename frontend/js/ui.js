const UI = {
    showNotification(message, type = 'info', duration = 3000) {
        const notification = document.getElementById('notification');
        if (!notification) return;

        notification.textContent = message;
        notification.className = `notification ${type} show`;

        setTimeout(() => {
            notification.classList.remove('show');
        }, duration);
    },

    showSuccess(message) {
        this.showNotification(message, 'success');
    },

    showError(message) {
        this.showNotification(message, 'error', 4000);
    },

    showWarning(message) {
        this.showNotification(message, 'warning', 3500);
    },

    showLoading(message = 'Loading...') {
        this.showNotification(message, 'info');
    },

    hideLoading() {
        const notification = document.getElementById('notification');
        if (notification) {
            notification.classList.remove('show');
        }
    },

    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    validatePassword(password) {
        return password.length >= 8;
    }
};
