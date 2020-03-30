const redirectToLandingPage = () => window.location.href = 'landing-page.html'
if (!getCookie('session-id')) redirectToLandingPage()
const cleanSessionAndRedirect = () => {
  cleanSessions()
  redirectToLandingPage()
}
