FROM coders51/ruby-phantomjs:latest

WORKDIR /app
VOLUME /app
EXPOSE 4567
ADD Gemfile* /app/
RUN bundle install
CMD ["bundle", "exec", "ruby", "app.rb"]
