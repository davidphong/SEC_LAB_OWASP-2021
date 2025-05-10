// Common JavaScript functionality for Security Lab

// Add loading state to buttons when clicked
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('btn') && !e.target.classList.contains('btn-no-loading')) {
        const btn = e.target;
        const originalText = btn.innerHTML;
        
        // Only apply to buttons not being used for form submission
        if (!btn.closest('form') || btn.type !== 'submit') {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
            
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }, 500);
        }
    }
});

// Enable tooltips everywhere
document.addEventListener('DOMContentLoaded', () => {
    try {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    } catch (e) {
        // Bootstrap might not be fully loaded yet
        console.log('Tooltips not initialized:', e);
    }
});

// Flash message auto-hide
document.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease-in-out';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 3000);
    });
});

// Create a data URL placeholder image
function createPlaceholder(width, height, text) {
    const canvas = document.createElement('canvas');
    canvas.width = width || 300;
    canvas.height = height || 200;
    const ctx = canvas.getContext('2d');
    
    // Background
    ctx.fillStyle = '#f0f0f0';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Border
    ctx.strokeStyle = '#dddddd';
    ctx.lineWidth = 2;
    ctx.strokeRect(0, 0, canvas.width, canvas.height);
    
    // Text
    ctx.fillStyle = '#888888';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text || 'VNPT Security', canvas.width / 2, canvas.height / 2);
    
    return canvas.toDataURL('image/png');
}

// Replace missing images with placeholders
document.addEventListener('DOMContentLoaded', function() {
    // Create and inject the placeholder image
    const placeholderImg = document.createElement('img');
    placeholderImg.src = createPlaceholder(300, 200, 'VNPT Security');
    placeholderImg.style.display = 'none';
    placeholderImg.id = 'default-placeholder';
    document.body.appendChild(placeholderImg);
    
    // Save a direct reference to the placeholder.png in the images folder
    // This helps avoid endless error loops
    const imageBasePath = document.querySelector('link[rel="stylesheet"]').href.replace(/css\/style\.css$/, '');
    const placeholderPath = imageBasePath + 'images/placeholder.png';
    
    fetch(placeholderPath)
        .then(response => {
            if (!response.ok) {
                console.log('Placeholder image not found, using generated one');
                
                // Create the placeholder image in the static folder
                const allImgs = document.querySelectorAll('img[onerror]');
                allImgs.forEach(img => {
                    if (img.getAttribute('onerror').includes('placeholder.png')) {
                        // Replace the onerror handler to use our data URL instead
                        img.onerror = function() {
                            this.onerror = null; // Prevent infinite loops
                            this.src = document.getElementById('default-placeholder').src;
                        };
                    }
                });
            }
        })
        .catch(err => {
            console.error('Error checking placeholder:', err);
        });
}); 