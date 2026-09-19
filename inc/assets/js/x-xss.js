const originalFetch = window.fetch;

window.fetch = async (...args) => {
  const [input, init = {}] = args; 

  const modifiedInit = {
    ...init,
    headers: {
      ...init.headers, 
      'X-XSS-Protection': '0', 
    },
  };

  return originalFetch(input, modifiedInit);
};