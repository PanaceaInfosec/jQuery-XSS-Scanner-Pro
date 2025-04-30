// Handle close button click when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('closeButton').addEventListener('click', function(e) {
    e.preventDefault();
    window.close();
  });
});