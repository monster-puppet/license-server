/* Shared Admin JavaScript */

// User menu toggle
function toggleUserMenu(event) {
    event.stopPropagation();
    const menu = document.getElementById('userMenu');
    menu.classList.toggle('active');
}

// Close menu when clicking outside
document.addEventListener('click', function(e) {
    const menu = document.getElementById('userMenu');
    const userInfo = document.querySelector('.user-info');
    if (menu && userInfo && !userInfo.contains(e.target)) {
        menu.classList.remove('active');
    }
});

// Close menu on escape
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        const menu = document.getElementById('userMenu');
        if (menu) menu.classList.remove('active');
    }
});
