(function () {
  'use strict';
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || !form.dataset || !form.dataset.agConfirm) {
      return;
    }
    if (!window.confirm(form.dataset.agConfirm)) {
      event.preventDefault();
    }
  });
})();
